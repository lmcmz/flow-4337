/**
 * @file FlowControlledService.ts
 * @description Main service class for Flow-controlled ERC-4337 accounts
 * Orchestrates bundler, wallet, and smart contract interactions
 */

import { FlowControlledBundler } from '../bundler/FlowControlledBundler';
import { FlowControlledWallet } from '../wallet/FlowControlledWallet';
import {
    BundlerConfig,
    FlowWalletConfig,
    UserOpExecutionRequest,
    FlowControlledUserOp,
    SignatureAlgorithm,
    FlowControlledError,
    FlowControlledAccountError
} from '../types/flow-controlled';

export interface FlowControlledServiceConfig {
    bundler: BundlerConfig;
    wallet: FlowWalletConfig;
    smartAccountAddress?: string;
}

export class FlowControlledService {
    private bundler: FlowControlledBundler;
    private wallet: FlowControlledWallet;
    private config: FlowControlledServiceConfig;
    private isInitialized: boolean = false;

    constructor(config: FlowControlledServiceConfig) {
        this.config = config;
        this.bundler = new FlowControlledBundler(config.bundler);
        this.wallet = new FlowControlledWallet(config.wallet);
    }

    /**
     * Initialize the service
     */
    async initialize(): Promise<void> {
        if (this.isInitialized) {
            return;
        }

        try {
            // Start bundler service
            await this.bundler.start();
            
            // Initialize wallet (doesn't auto-authenticate)
            console.log("Flow-controlled service initialized");
            
            this.isInitialized = true;
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.BUNDLER_NOT_AUTHORIZED,
                "Failed to initialize Flow-controlled service",
                error
            );
        }
    }

    /**
     * Shutdown the service
     */
    async shutdown(): Promise<void> {
        if (!this.isInitialized) {
            return;
        }

        try {
            await this.bundler.stop();
            await this.wallet.disconnect();
            
            this.isInitialized = false;
            console.log("Flow-controlled service shutdown");
        } catch (error) {
            console.error("Error during service shutdown:", error);
        }
    }

    /**
     * Authenticate with Flow wallet
     */
    async authenticateWallet(): Promise<string> {
        await this.wallet.authenticate();
        const address = this.wallet.getCurrentAddress();
        
        if (!address) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "Failed to get Flow address after authentication"
            );
        }

        // Add Flow account to bundler monitoring
        await this.bundler.addFlowAccount(address);
        
        return address;
    }

    /**
     * Disconnect wallet
     */
    async disconnectWallet(): Promise<void> {
        const address = this.wallet.getCurrentAddress();
        if (address) {
            await this.bundler.removeFlowAccount(address);
        }
        await this.wallet.disconnect();
    }

    /**
     * Execute a smart contract call via Flow-controlled account
     */
    async executeCall(
        target: string,
        data: string,
        value: string = "0",
        options: {
            gasLimit?: string;
            gasPrice?: string;
            signatureAlgorithm?: SignatureAlgorithm;
            keyIndex?: number;
        } = {}
    ): Promise<string> {
        if (!this.wallet.isAuthenticated()) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        // Create execution request
        const request = await this.wallet.createExecutionRequest(
            target,
            data,
            value,
            options.gasLimit || "200000",
            options.gasPrice,
            options.signatureAlgorithm || SignatureAlgorithm.ECDSA_secp256k1,
            options.keyIndex
        );

        // Get Merkle proof from bundler
        const proof = await this.bundler.getMerkleProof(
            request.userOp.flowAddress,
            request.userOp.publicKey
        );
        
        // Update user operation with proof
        request.userOp.merkleProof = proof;

        // Process through bundler
        return await this.bundler.processUserOp(request);
    }

    /**
     * Execute multiple calls in batch
     */
    async executeBatch(
        operations: Array<{
            target: string;
            data: string;
            value?: string;
            signatureAlgorithm?: SignatureAlgorithm;
            keyIndex?: number;
        }>,
        batchOptions: {
            gasLimit?: string;
            gasPrice?: string;
        } = {}
    ): Promise<string[]> {
        if (!this.wallet.isAuthenticated()) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        const requests: UserOpExecutionRequest[] = [];
        
        for (const op of operations) {
            const request = await this.wallet.createExecutionRequest(
                op.target,
                op.data,
                op.value || "0",
                batchOptions.gasLimit || "200000",
                batchOptions.gasPrice,
                op.signatureAlgorithm || SignatureAlgorithm.ECDSA_secp256k1,
                op.keyIndex
            );

            // Get Merkle proof
            const proof = await this.bundler.getMerkleProof(
                request.userOp.flowAddress,
                request.userOp.publicKey
            );
            
            request.userOp.merkleProof = proof;
            requests.push(request);
        }

        return await this.bundler.batchProcessUserOps(requests);
    }

    /**
     * Get service status
     */
    async getStatus() {
        const walletInfo = this.wallet.getWalletInfo();
        const bundlerStats = await this.bundler.getBundlerStats();
        
        let accountState = null;
        if (walletInfo.address) {
            accountState = await this.bundler.getFlowAccountState(walletInfo.address);
        }

        return {
            isInitialized: this.isInitialized,
            wallet: walletInfo,
            bundler: bundlerStats,
            flowAccount: accountState,
            config: {
                flowEndpoint: this.config.bundler.flowEndpoint,
                evmEndpoint: this.config.bundler.evmEndpoint,
                smartAccountAddress: this.config.smartAccountAddress
            }
        };
    }

    /**
     * Get available Flow keys
     */
    getAvailableKeys() {
        return this.wallet.getAvailableKeys();
    }

    /**
     * Get keys by signature algorithm
     */
    getKeysByAlgorithm(algorithm: SignatureAlgorithm) {
        return this.wallet.getKeysByAlgorithm(algorithm);
    }

    /**
     * Refresh Flow keys
     */
    async refreshKeys(): Promise<void> {
        await this.wallet.refreshKeys();
    }

    /**
     * Check if root is fresh for current Flow account
     */
    async checkRootFreshness(): Promise<boolean> {
        const address = this.wallet.getCurrentAddress();
        if (!address) {
            return false;
        }
        return await this.bundler.checkRootFreshness(address);
    }

    /**
     * Force update Merkle root for current Flow account
     */
    async forceRootUpdate(): Promise<string> {
        const address = this.wallet.getCurrentAddress();
        if (!address) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                "No authenticated Flow address"
            );
        }

        const merkleTree = await this.bundler.buildMerkleTree(address);
        const update = {
            flowAddress: address,
            merkleRoot: merkleTree.root,
            blockHeight: merkleTree.blockHeight,
            keyCount: merkleTree.totalKeys,
            timestamp: Date.now()
        };

        return await this.bundler.updateRoot(update);
    }

    /**
     * Get bundler reference (for advanced usage)
     */
    getBundler(): FlowControlledBundler {
        return this.bundler;
    }

    /**
     * Get wallet reference (for advanced usage)
     */
    getWallet(): FlowControlledWallet {
        return this.wallet;
    }
}