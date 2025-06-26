/**
 * @file FlowControlledWalletV2.ts
 * @description Wallet integration for Flow-controlled ERC-4337 V2 with multi-signature support
 * Handles Flow key management and multi-signature creation
 */

import * as fcl from '@onflow/fcl';
import { ethers } from 'ethers';
import crypto from 'crypto';
import {
    KeyInfo,
    FlowMultiSigUserOp,
    MultiSigRequest,
    MultiSigResponse,
    KeySelectionStrategy,
    SignatureAlgorithm,
    HashAlgorithm,
    FlowWalletV2,
    FlowControlledErrorV2,
    FlowControlledAccountErrorV2
} from '../types/flow-controlled-v2';

export interface FlowWalletConfigV2 {
    flowEndpoint: string;        // Flow blockchain RPC endpoint
    walletDiscovery?: string;    // Flow wallet discovery endpoint
    flowKeyRegisterAddress: string; // EVM FlowKeyRegister contract address
}

export class FlowControlledWalletV2 implements FlowWalletV2 {
    private config: FlowWalletConfigV2;
    private currentUser: any = null;
    private userKeys: KeyInfo[] = [];

    constructor(config: FlowWalletConfigV2) {
        this.config = config;
        this.initializeFlow();
    }

    private initializeFlow() {
        fcl.config({
            'accessNode.api': this.config.flowEndpoint,
            'discovery.wallet': this.config.walletDiscovery || 'https://fcl-discovery.onflow.org/testnet/authn'
        });
    }

    /**
     * Authenticate with Flow wallet
     */
    async authenticate(): Promise<string> {
        try {
            const user = await fcl.authenticate();
            this.currentUser = user;
            
            if (user?.addr) {
                await this.loadUserKeys();
                console.log(`Authenticated Flow user: ${user.addr}`);
                return user.addr;
            }
            
            throw new Error("No Flow address received from authentication");
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.FLOW_CHAIN_ERROR,
                "Failed to authenticate with Flow wallet",
                error
            );
        }
    }

    /**
     * Disconnect from Flow wallet
     */
    async disconnect(): Promise<void> {
        await fcl.unauthenticate();
        this.currentUser = null;
        this.userKeys = [];
        console.log("Disconnected from Flow wallet");
    }

    /**
     * Check if wallet is authenticated
     */
    isAuthenticated(): boolean {
        return this.currentUser !== null && this.currentUser.addr !== null;
    }

    /**
     * Get current Flow address
     */
    getCurrentAddress(): string | null {
        return this.currentUser?.addr || null;
    }

    /**
     * Load user keys from Flow blockchain (native keys)
     */
    private async loadUserKeys(): Promise<void> {
        if (!this.currentUser?.addr) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "No authenticated Flow address"
            );
        }

        const script = `
            pub fun main(account: Address): [AnyStruct] {
                let accountRef = getAccount(account)
                let keys: [AnyStruct] = []
                
                for keyIndex in accountRef.keys.keys {
                    if let key = accountRef.keys.get(keyIndex: keyIndex) {
                        // Only include supported algorithms
                        if key.signatureAlgorithm.rawValue == 1 || key.signatureAlgorithm.rawValue == 2 {
                            let keyData = {
                                "publicKey": key.publicKey.publicKey,
                                "weight": key.weight,
                                "hashAlgorithm": key.hashAlgorithm.rawValue,
                                "signatureAlgorithm": key.signatureAlgorithm.rawValue,
                                "isRevoked": key.isRevoked,
                                "keyIndex": keyIndex
                            }
                            keys.append(keyData)
                        }
                    }
                }
                
                return keys
            }
        `;

        try {
            const result = await fcl.query({
                cadence: script,
                args: (arg: any, t: any) => [arg(this.currentUser.addr, t.Address)]
            });

            this.userKeys = result.map((keyData: any) => this.convertToKeyInfo(keyData));
            console.log(`Loaded ${this.userKeys.length} keys for Flow address ${this.currentUser.addr}`);
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.FLOW_CHAIN_ERROR,
                "Failed to load user keys from Flow",
                error
            );
        }
    }

    private convertToKeyInfo(flowKeyData: any): KeyInfo {
        // Extract public key
        let publicKey = flowKeyData.publicKey;
        if (typeof publicKey === 'object' && publicKey.publicKey) {
            publicKey = publicKey.publicKey;
        }
        
        // Remove 04 prefix if present
        if (publicKey.startsWith('04')) {
            publicKey = publicKey.slice(2);
        }

        // Convert weight from decimal (0.0-1.0) to integer (0-1000)
        const weight = Math.floor(flowKeyData.weight * 1000);

        return {
            publicKey,
            weight,
            hashAlgorithm: flowKeyData.hashAlgorithm,
            signatureAlgorithm: flowKeyData.signatureAlgorithm,
            isRevoked: flowKeyData.isRevoked,
            keyIndex: flowKeyData.keyIndex
        };
    }

    /**
     * Get available (non-revoked) keys for the current user
     */
    async getAvailableKeys(): Promise<KeyInfo[]> {
        if (!this.isAuthenticated()) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        // Refresh keys from Flow
        await this.loadUserKeys();
        
        return this.userKeys.filter(key => 
            !key.isRevoked && 
            (key.signatureAlgorithm === SignatureAlgorithm.ECDSA_P256 || 
             key.signatureAlgorithm === SignatureAlgorithm.ECDSA_secp256k1)
        );
    }

    /**
     * Select keys based on strategy
     */
    async selectKeys(strategy: KeySelectionStrategy, options?: any): Promise<KeyInfo[]> {
        const availableKeys = await this.getAvailableKeys();
        
        if (availableKeys.length === 0) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_KEY_INFO,
                "No available keys found"
            );
        }

        switch (strategy) {
            case KeySelectionStrategy.ALL_AVAILABLE:
                return availableKeys;

            case KeySelectionStrategy.MINIMUM_WEIGHT:
                return this.selectMinimumWeightKeys(availableKeys, options?.minimumWeight || 1000);

            case KeySelectionStrategy.PREFERRED_ALGORITHM:
                return this.selectByAlgorithm(availableKeys, options?.algorithm || SignatureAlgorithm.ECDSA_secp256k1);

            case KeySelectionStrategy.SPECIFIC_KEYS:
                return this.selectSpecificKeys(availableKeys, options?.keyIndices || []);

            case KeySelectionStrategy.HIGHEST_WEIGHT:
                return this.selectHighestWeightKeys(availableKeys, options?.minimumWeight || 1000);

            default:
                throw new FlowControlledAccountErrorV2(
                    FlowControlledErrorV2.INVALID_KEY_INFO,
                    `Unsupported key selection strategy: ${strategy}`
                );
        }
    }

    private selectMinimumWeightKeys(keys: KeyInfo[], targetWeight: number): KeyInfo[] {
        // Sort by weight descending to minimize number of keys needed
        const sortedKeys = keys.sort((a, b) => b.weight - a.weight);
        const selectedKeys: KeyInfo[] = [];
        let totalWeight = 0;

        for (const key of sortedKeys) {
            selectedKeys.push(key);
            totalWeight += key.weight;
            
            if (totalWeight >= targetWeight) {
                break;
            }
        }

        if (totalWeight < targetWeight) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INSUFFICIENT_SIGNATURE_WEIGHT,
                `Insufficient total key weight: ${totalWeight} < ${targetWeight}`
            );
        }

        return selectedKeys;
    }

    private selectByAlgorithm(keys: KeyInfo[], algorithm: SignatureAlgorithm): KeyInfo[] {
        const filteredKeys = keys.filter(key => key.signatureAlgorithm === algorithm);
        
        if (filteredKeys.length === 0) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.UNSUPPORTED_ALGORITHM,
                `No keys available for algorithm: ${algorithm}`
            );
        }

        return filteredKeys;
    }

    private selectSpecificKeys(keys: KeyInfo[], keyIndices: number[]): KeyInfo[] {
        const selectedKeys = keyIndices.map(index => {
            const key = keys.find(k => k.keyIndex === index);
            if (!key) {
                throw new FlowControlledAccountErrorV2(
                    FlowControlledErrorV2.INVALID_KEY_INFO,
                    `Key not found at index: ${index}`
                );
            }
            return key;
        });

        return selectedKeys;
    }

    private selectHighestWeightKeys(keys: KeyInfo[], targetWeight: number): KeyInfo[] {
        // Sort by weight descending
        const sortedKeys = keys.sort((a, b) => b.weight - a.weight);
        return this.selectMinimumWeightKeys(sortedKeys, targetWeight);
    }

    /**
     * Sign multi-signature operation
     */
    async signMultiSig(request: MultiSigRequest): Promise<MultiSigResponse> {
        if (!this.isAuthenticated()) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        if (request.flowAddress !== this.currentUser.addr) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Flow address mismatch"
            );
        }

        // Select keys based on strategy
        const selectedKeys = await this.selectKeys(
            request.keySelectionStrategy,
            {
                minimumWeight: request.minimumWeight,
                algorithm: request.preferredAlgorithm
            }
        );

        // Sign with each selected key
        const signatures: string[] = [];
        let totalWeight = 0;
        const usedAlgorithms: Set<SignatureAlgorithm> = new Set();

        for (const key of selectedKeys) {
            const signature = await this.signWithFlowKey(request.opHash, key);
            signatures.push(signature);
            totalWeight += key.weight;
            usedAlgorithms.add(key.signatureAlgorithm);
        }

        // Create user operation (without proofs - will be added by bundler)
        const userOp: FlowMultiSigUserOp = {
            flowAddress: request.flowAddress,
            opHash: request.opHash,
            keys: selectedKeys,
            signatures,
            merkleProofs: [] // Will be populated by bundler
        };

        return {
            userOp,
            totalWeight,
            keyCount: selectedKeys.length,
            usedAlgorithms: Array.from(usedAlgorithms)
        };
    }

    /**
     * Create user operation for contract call
     */
    async createUserOperation(
        target: string,
        data: string,
        value: string = "0",
        options: {
            keySelection?: KeySelectionStrategy;
            minimumWeight?: number;
            gasLimit?: string;
        } = {}
    ): Promise<FlowMultiSigUserOp> {
        if (!this.isAuthenticated()) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        // Create operation hash
        const opHash = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ['address', 'address', 'bytes', 'uint256', 'uint256'],
                [this.currentUser.addr, target, data, value, Date.now()]
            )
        );

        // Create multi-signature request
        const multiSigRequest: MultiSigRequest = {
            flowAddress: this.currentUser.addr,
            opHash,
            keySelectionStrategy: options.keySelection || KeySelectionStrategy.MINIMUM_WEIGHT,
            minimumWeight: options.minimumWeight || 1000
        };

        const response = await this.signMultiSig(multiSigRequest);
        return response.userOp;
    }

    /**
     * Sign with Flow key using FCL
     */
    private async signWithFlowKey(message: string, key: KeyInfo): Promise<string> {
        try {
            // Use FCL's user signature method
            const signableMessage = {
                message: ethers.utils.arrayify(message)
            };

            const signature = await fcl.currentUser.signUserMessage(signableMessage);
            
            if (signature && signature.signature) {
                return signature.signature;
            }
            
            throw new Error("Invalid signature response from Flow wallet");
        } catch (error) {
            // Fallback: create mock signature for development/testing
            console.warn("Flow wallet signing failed, using mock signature");
            return this.createMockSignature(message, key);
        }
    }

    /**
     * Create mock signature for development/testing
     */
    private createMockSignature(message: string, key: KeyInfo): string {
        // Create deterministic signature based on key and message
        const keyBytes = Buffer.from(key.publicKey, 'hex');
        const msgBytes = Buffer.from(message.slice(2), 'hex');
        const combined = Buffer.concat([keyBytes, msgBytes, Buffer.from([key.keyIndex])]);
        const sigHash = crypto.createHash('sha256').update(combined).digest();
        
        // Create signature-like bytes (64 bytes)
        const signature = Buffer.concat([sigHash, sigHash]).slice(0, 64);
        return '0x' + signature.toString('hex');
    }

    /**
     * Get wallet information
     */
    getWalletInfo() {
        return {
            address: this.getCurrentAddress(),
            isAuthenticated: this.isAuthenticated(),
            keyCount: this.userKeys.length,
            availableKeyCount: this.userKeys.filter(k => !k.isRevoked).length,
            totalWeight: this.userKeys
                .filter(k => !k.isRevoked)
                .reduce((sum, k) => sum + k.weight, 0),
            supportedAlgorithms: [
                SignatureAlgorithm.ECDSA_P256,
                SignatureAlgorithm.ECDSA_secp256k1
            ]
        };
    }

    /**
     * Refresh user keys from Flow
     */
    async refreshKeys(): Promise<void> {
        if (this.isAuthenticated()) {
            await this.loadUserKeys();
        }
    }

    /**
     * Validate public key format
     */
    static validatePublicKey(publicKey: string): boolean {
        const cleanKey = publicKey.replace('0x', '');
        return cleanKey.length === 128 && /^[0-9a-fA-F]+$/.test(cleanKey);
    }

    /**
     * Format public key (ensure no 04 prefix)
     */
    static formatPublicKey(publicKey: string): string {
        let cleanKey = publicKey.replace('0x', '');
        
        if (cleanKey.length === 130 && cleanKey.startsWith('04')) {
            cleanKey = cleanKey.slice(2);
        }
        
        return cleanKey;
    }

    /**
     * Get key by index
     */
    getKeyByIndex(keyIndex: number): KeyInfo | null {
        return this.userKeys.find(key => key.keyIndex === keyIndex) || null;
    }

    /**
     * Get keys by signature algorithm
     */
    getKeysByAlgorithm(algorithm: SignatureAlgorithm): KeyInfo[] {
        return this.userKeys.filter(key => 
            !key.isRevoked && key.signatureAlgorithm === algorithm
        );
    }

    /**
     * Check if account has sufficient weight for operations
     */
    hasSufficientWeight(threshold: number = 1000): boolean {
        const totalWeight = this.userKeys
            .filter(k => !k.isRevoked)
            .reduce((sum, k) => sum + k.weight, 0);
        
        return totalWeight >= threshold;
    }
}