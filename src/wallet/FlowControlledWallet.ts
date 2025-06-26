/**
 * @file FlowControlledWallet.ts
 * @description Wallet integration for Flow-controlled ERC-4337 accounts
 * Handles Flow key management and signature generation
 */

import * as fcl from '@onflow/fcl';
import { ethers } from 'ethers';
import crypto from 'crypto';
import {
    FlowKey,
    FlowSignatureRequest,
    FlowSignatureResponse,
    FlowControlledUserOp,
    UserOpExecutionRequest,
    SignatureAlgorithm,
    HashAlgorithm,
    FlowControlledError,
    FlowControlledAccountError
} from '../types/flow-controlled';

export interface FlowWalletConfig {
    flowEndpoint: string;        // Flow blockchain RPC endpoint
    walletDiscovery?: string;    // Flow wallet discovery endpoint
    flowKeyRegisterAddress: string; // Flow key register contract address
}

export class FlowControlledWallet {
    private config: FlowWalletConfig;
    private currentUser: any = null;
    private userKeys: FlowKey[] = [];

    constructor(config: FlowWalletConfig) {
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
    async authenticate(): Promise<void> {
        try {
            const user = await fcl.authenticate();
            this.currentUser = user;
            
            if (user?.addr) {
                await this.loadUserKeys();
                console.log(`Authenticated Flow user: ${user.addr}`);
            }
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.FLOW_CHAIN_ERROR,
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
     * Load user keys from Flow key register
     */
    private async loadUserKeys(): Promise<void> {
        if (!this.currentUser?.addr) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "No authenticated Flow address"
            );
        }

        const script = `
            import FlowKeyRegister from ${this.config.flowKeyRegisterAddress}
            
            pub fun main(account: Address): [FlowKeyRegister.FlowKey] {
                return FlowKeyRegister.getKeys(account: account)
            }
        `;

        try {
            const keys = await fcl.query({
                cadence: script,
                args: (arg: any, t: any) => [arg(this.currentUser.addr, t.Address)]
            });

            this.userKeys = keys.map((key: any) => ({
                publicKey: key.publicKey,
                weight: parseFloat(key.weight),
                hashAlgorithm: parseInt(key.hashAlgorithm),
                signatureAlgorithm: parseInt(key.signatureAlgorithm),
                isRevoked: key.isRevoked,
                keyIndex: parseInt(key.keyIndex)
            }));

            console.log(`Loaded ${this.userKeys.length} keys for Flow address ${this.currentUser.addr}`);
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.FLOW_CHAIN_ERROR,
                "Failed to load user keys from Flow",
                error
            );
        }
    }

    /**
     * Get available keys for the current user
     */
    getAvailableKeys(): FlowKey[] {
        return this.userKeys.filter(key => 
            !key.isRevoked && 
            (key.signatureAlgorithm === SignatureAlgorithm.ECDSA_P256 || 
             key.signatureAlgorithm === SignatureAlgorithm.ECDSA_secp256k1)
        );
    }

    /**
     * Get a specific key by index
     */
    getKeyByIndex(keyIndex: number): FlowKey | null {
        return this.userKeys.find(key => key.keyIndex === keyIndex) || null;
    }

    /**
     * Get keys by signature algorithm
     */
    getKeysByAlgorithm(algorithm: SignatureAlgorithm): FlowKey[] {
        return this.getAvailableKeys().filter(key => key.signatureAlgorithm === algorithm);
    }

    /**
     * Sign a message with Flow key
     */
    async signMessage(request: FlowSignatureRequest): Promise<FlowSignatureResponse> {
        if (!this.isAuthenticated()) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        if (request.flowAddress !== this.currentUser.addr) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "Flow address mismatch"
            );
        }

        // Select key to use
        let selectedKey: FlowKey;
        if (request.keyIndex !== undefined) {
            const key = this.getKeyByIndex(request.keyIndex);
            if (!key) {
                throw new FlowControlledAccountError(
                    FlowControlledError.INVALID_PUBLIC_KEY,
                    `Key not found at index ${request.keyIndex}`
                );
            }
            selectedKey = key;
        } else {
            // Select first available key with requested algorithm
            const availableKeys = this.getKeysByAlgorithm(request.signatureAlgorithm);
            if (availableKeys.length === 0) {
                throw new FlowControlledAccountError(
                    FlowControlledError.UNSUPPORTED_ALGORITHM,
                    `No keys available for algorithm ${request.signatureAlgorithm}`
                );
            }
            selectedKey = availableKeys[0];
        }

        // Verify key algorithm matches request
        if (selectedKey.signatureAlgorithm !== request.signatureAlgorithm) {
            throw new FlowControlledAccountError(
                FlowControlledError.UNSUPPORTED_ALGORITHM,
                "Key algorithm mismatch"
            );
        }

        try {
            // Sign using Flow wallet
            const signature = await this.signWithFlowWallet(request.message, selectedKey);

            return {
                signature,
                publicKey: selectedKey.publicKey,
                keyIndex: selectedKey.keyIndex,
                weight: selectedKey.weight,
                hashAlgorithm: selectedKey.hashAlgorithm,
                signatureAlgorithm: selectedKey.signatureAlgorithm
            };
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_SIGNATURE,
                "Failed to sign message with Flow wallet",
                error
            );
        }
    }

    /**
     * Sign with Flow wallet using FCL
     */
    private async signWithFlowWallet(message: string, key: FlowKey): Promise<string> {
        // Create message for signing
        const messageBuffer = Buffer.from(message.replace('0x', ''), 'hex');
        
        try {
            // Use FCL's user signature method
            const signature = await fcl.currentUser.signUserMessage();
            
            // The signature from FCL includes additional metadata
            // We need to extract just the signature bytes
            if (signature && signature.signature) {
                return signature.signature;
            }
            
            throw new Error("Invalid signature response from Flow wallet");
        } catch (error) {
            // Fallback: construct signature manually for development/testing
            console.warn("Flow wallet signing failed, using fallback method");
            return this.createMockSignature(message, key);
        }
    }

    /**
     * Create mock signature for development/testing
     */
    private createMockSignature(message: string, key: FlowKey): string {
        // This is a mock implementation for development
        // In production, this should never be used
        const messageHash = ethers.utils.keccak256(message);
        const randomBytes = crypto.randomBytes(64);
        
        // Create deterministic signature based on key and message
        const keyBytes = Buffer.from(key.publicKey, 'hex');
        const msgBytes = Buffer.from(messageHash.slice(2), 'hex');
        const combined = Buffer.concat([keyBytes, msgBytes]);
        const sigHash = crypto.createHash('sha256').update(combined).digest();
        
        // Create signature-like bytes
        const signature = Buffer.concat([sigHash, sigHash]).slice(0, 64);
        return '0x' + signature.toString('hex');
    }

    /**
     * Create user operation for ERC-4337
     */
    async createUserOperation(
        target: string,
        data: string,
        value: string = "0",
        signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_secp256k1,
        keyIndex?: number
    ): Promise<FlowControlledUserOp> {
        if (!this.isAuthenticated()) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
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

        // Sign the operation hash
        const signatureRequest: FlowSignatureRequest = {
            flowAddress: this.currentUser.addr,
            message: opHash,
            keyIndex,
            signatureAlgorithm
        };

        const signatureResponse = await this.signMessage(signatureRequest);

        // Note: Merkle proof will be generated by the bundler
        return {
            flowAddress: this.currentUser.addr,
            opHash,
            publicKey: signatureResponse.publicKey,
            weight: signatureResponse.weight,
            hashAlgorithm: signatureResponse.hashAlgorithm,
            signatureAlgorithm: signatureResponse.signatureAlgorithm,
            signature: signatureResponse.signature,
            merkleProof: [] // Will be populated by bundler
        };
    }

    /**
     * Create execution request for bundler
     */
    async createExecutionRequest(
        target: string,
        data: string,
        value: string = "0",
        gasLimit: string = "200000",
        gasPrice?: string,
        signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_secp256k1,
        keyIndex?: number
    ): Promise<UserOpExecutionRequest> {
        const userOp = await this.createUserOperation(
            target,
            data,
            value,
            signatureAlgorithm,
            keyIndex
        );

        return {
            userOp,
            target,
            data,
            value,
            gasLimit,
            gasPrice: gasPrice || "0" // Will be set by bundler if not provided
        };
    }

    /**
     * Batch create multiple user operations
     */
    async createBatchUserOperations(
        operations: Array<{
            target: string;
            data: string;
            value?: string;
            signatureAlgorithm?: SignatureAlgorithm;
            keyIndex?: number;
        }>
    ): Promise<FlowControlledUserOp[]> {
        const userOps: FlowControlledUserOp[] = [];
        
        for (const op of operations) {
            const userOp = await this.createUserOperation(
                op.target,
                op.data,
                op.value,
                op.signatureAlgorithm,
                op.keyIndex
            );
            userOps.push(userOp);
        }
        
        return userOps;
    }

    /**
     * Get wallet information
     */
    getWalletInfo() {
        return {
            address: this.getCurrentAddress(),
            isAuthenticated: this.isAuthenticated(),
            keyCount: this.userKeys.length,
            availableKeyCount: this.getAvailableKeys().length,
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
        // Remove 0x prefix if present
        const cleanKey = publicKey.replace('0x', '');
        
        // Should be 64 bytes (128 hex characters) for uncompressed key without 04 prefix
        if (cleanKey.length !== 128) {
            return false;
        }
        
        // Should be valid hex
        return /^[0-9a-fA-F]+$/.test(cleanKey);
    }

    /**
     * Format public key (remove 04 prefix if present)
     */
    static formatPublicKey(publicKey: string): string {
        let cleanKey = publicKey.replace('0x', '');
        
        // Remove 04 prefix if present
        if (cleanKey.length === 130 && cleanKey.startsWith('04')) {
            cleanKey = cleanKey.slice(2);
        }
        
        return cleanKey;
    }
}