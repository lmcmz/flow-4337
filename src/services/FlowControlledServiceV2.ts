/**
 * @file FlowControlledServiceV2.ts
 * @description Main service class for Flow-controlled ERC-4337 V2 with multi-signature support
 * Orchestrates CREATE2 factory, bundler, and wallet interactions
 */

import { FlowControlledBundlerV2 } from '../bundler/FlowControlledBundlerV2';
import { FlowControlledWalletV2 } from '../wallet/FlowControlledWalletV2';
import {
    FlowControlledServiceConfigV2,
    AccountCreationRequest,
    AccountCreationResponse,
    MultiSigRequest,
    MultiSigResponse,
    UserOpExecutionRequestV2,
    BatchExecutionRequest,
    KeySelectionStrategy,
    SignatureAlgorithm,
    BundlerStatsV2,
    FlowAccountMonitorV2,
    KeyMismatchResult,
    FlowControlledErrorV2,
    FlowControlledAccountErrorV2
} from '../types/flow-controlled-v2';

export class FlowControlledServiceV2 {
    private bundler: FlowControlledBundlerV2;
    private wallet: FlowControlledWalletV2;
    private config: FlowControlledServiceConfigV2;
    private isInitialized: boolean = false;

    constructor(config: FlowControlledServiceConfigV2) {
        this.config = config;
        this.bundler = new FlowControlledBundlerV2(config.bundler);
        this.wallet = new FlowControlledWalletV2({
            flowEndpoint: config.bundler.flowEndpoint,
            flowKeyRegisterAddress: config.flowKeyRegister
        });
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
            
            console.log("Flow-controlled service V2 initialized");
            this.isInitialized = true;
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.BUNDLER_NOT_AUTHORIZED,
                "Failed to initialize Flow-controlled service V2",
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
            console.log("Flow-controlled service V2 shutdown");
        } catch (error) {
            console.error("Error during service shutdown:", error);
        }
    }

    /**
     * Authenticate with Flow wallet and set up account monitoring
     */
    async authenticateWallet(): Promise<string> {
        const flowAddress = await this.wallet.authenticate();
        
        if (!flowAddress) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Failed to get Flow address after authentication"
            );
        }

        // Add Flow account to bundler monitoring
        await this.bundler.addFlowAccount(flowAddress);
        
        return flowAddress;
    }

    /**
     * Disconnect wallet and stop monitoring
     */
    async disconnectWallet(): Promise<void> {
        const address = this.wallet.getCurrentAddress();
        if (address) {
            await this.bundler.removeFlowAccount(address);
        }
        await this.wallet.disconnect();
    }

    /**
     * Deploy or predict smart account address
     */
    async deploySmartAccount(
        flowAddress?: string,
        deployImmediately: boolean = true
    ): Promise<AccountCreationResponse> {
        const targetAddress = flowAddress || this.wallet.getCurrentAddress();
        
        if (!targetAddress) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "No Flow address provided or authenticated"
            );
        }

        const request: AccountCreationRequest = {
            flowAddress: targetAddress,
            deployImmediately,
            initialKeySync: true
        };

        return await this.bundler.deployAccount(request);
    }

    /**
     * Execute a smart contract call with multi-signature
     */
    async executeCall(
        target: string,
        data: string,
        value: string = "0",
        options: {
            gasLimit?: string;
            gasPrice?: string;
            keySelection?: KeySelectionStrategy;
            minimumWeight?: number;
            preferredAlgorithm?: SignatureAlgorithm;
        } = {}
    ): Promise<string> {
        if (!this.wallet.isAuthenticated()) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        const flowAddress = this.wallet.getCurrentAddress()!;

        // Create multi-signature user operation
        const multiSigUserOp = await this.wallet.createUserOperation(
            target,
            data,
            value,
            {
                keySelection: options.keySelection || KeySelectionStrategy.MINIMUM_WEIGHT,
                minimumWeight: options.minimumWeight || 1000,
                gasLimit: options.gasLimit || "200000"
            }
        );

        // Create execution request
        const request: UserOpExecutionRequestV2 = {
            multiSigUserOp,
            target,
            data,
            value,
            gasLimit: options.gasLimit || "200000",
            gasPrice: options.gasPrice
        };

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
            gasLimit?: string;
        }>,
        batchOptions: {
            gasPrice?: string;
            keySelection?: KeySelectionStrategy;
            minimumWeight?: number;
        } = {}
    ): Promise<string[]> {
        if (!this.wallet.isAuthenticated()) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        const userOps = [];
        const targets = [];
        const datas = [];
        const values = [];
        const gasLimits = [];

        for (const op of operations) {
            const multiSigUserOp = await this.wallet.createUserOperation(
                op.target,
                op.data,
                op.value || "0",
                {
                    keySelection: batchOptions.keySelection || KeySelectionStrategy.MINIMUM_WEIGHT,
                    minimumWeight: batchOptions.minimumWeight || 1000,
                    gasLimit: op.gasLimit || "200000"
                }
            );

            userOps.push(multiSigUserOp);
            targets.push(op.target);
            datas.push(op.data);
            values.push(op.value || "0");
            gasLimits.push(op.gasLimit || "200000");
        }

        const batchRequest: BatchExecutionRequest = {
            userOps,
            targets,
            datas,
            values,
            gasLimits,
            gasPrice: batchOptions.gasPrice
        };

        return await this.bundler.batchProcessUserOps(batchRequest);
    }

    /**
     * Create multi-signature for custom operation
     */
    async createMultiSignature(request: MultiSigRequest): Promise<MultiSigResponse> {
        if (!this.wallet.isAuthenticated()) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "Wallet not authenticated"
            );
        }

        return await this.wallet.signMultiSig(request);
    }

    /**
     * Check for key mismatches between Flow and EVM
     */
    async checkKeyMismatch(flowAddress?: string): Promise<KeyMismatchResult> {
        const targetAddress = flowAddress || this.wallet.getCurrentAddress();
        
        if (!targetAddress) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "No Flow address provided or authenticated"
            );
        }

        return await this.bundler.checkKeyMismatch(targetAddress);
    }

    /**
     * Force synchronization of Flow keys to EVM
     */
    async syncKeys(flowAddress?: string): Promise<boolean> {
        const targetAddress = flowAddress || this.wallet.getCurrentAddress();
        
        if (!targetAddress) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "No Flow address provided or authenticated"
            );
        }

        return await this.bundler.syncKeys(targetAddress);
    }

    /**
     * Get service status
     */
    async getStatus() {
        const walletInfo = this.wallet.getWalletInfo();
        const bundlerStats = await this.bundler.getBundlerStats();
        
        let accountState: FlowAccountMonitorV2 | null = null;
        let keyMismatch: KeyMismatchResult | null = null;
        
        if (walletInfo.address) {
            try {
                accountState = await this.bundler.getFlowAccountState(walletInfo.address);
                keyMismatch = await this.bundler.checkKeyMismatch(walletInfo.address);
            } catch (error) {
                // Account might not be monitored yet
            }
        }

        return {
            isInitialized: this.isInitialized,
            wallet: walletInfo,
            bundler: bundlerStats,
            flowAccount: accountState,
            keyMismatch,
            config: {
                flowEndpoint: this.config.bundler.flowEndpoint,
                evmEndpoint: this.config.bundler.evmEndpoint,
                flowKeyRegister: this.config.flowKeyRegister,
                rootRegistry: this.config.rootRegistry,
                factory: this.config.factory
            }
        };
    }

    /**
     * Get available Flow keys
     */
    async getAvailableKeys() {
        return await this.wallet.getAvailableKeys();
    }

    /**
     * Select keys based on strategy
     */
    async selectKeys(
        strategy: KeySelectionStrategy,
        options?: any
    ) {
        return await this.wallet.selectKeys(strategy, options);
    }

    /**
     * Check if root is fresh for current Flow account
     */
    async checkRootFreshness(flowAddress?: string): Promise<boolean> {
        const targetAddress = flowAddress || this.wallet.getCurrentAddress();
        
        if (!targetAddress) {
            return false;
        }
        
        return await this.bundler.checkRootFreshness(targetAddress);
    }

    /**
     * Force update Merkle root for Flow account
     */
    async forceRootUpdate(flowAddress?: string): Promise<string> {
        const targetAddress = flowAddress || this.wallet.getCurrentAddress();
        
        if (!targetAddress) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "No Flow address provided or authenticated"
            );
        }

        const merkleTree = await this.bundler.buildKeyInfoMerkleTree(targetAddress);
        return await this.bundler.updateRoot(targetAddress, merkleTree);
    }

    /**
     * Get predicted smart account address
     */
    async predictAccountAddress(flowAddress?: string): Promise<string> {
        const targetAddress = flowAddress || this.wallet.getCurrentAddress();
        
        if (!targetAddress) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                "No Flow address provided or authenticated"
            );
        }

        return await this.bundler.predictAccountAddress(targetAddress);
    }

    /**
     * Get bundler reference (for advanced usage)
     */
    getBundler(): FlowControlledBundlerV2 {
        return this.bundler;
    }

    /**
     * Get wallet reference (for advanced usage)
     */
    getWallet(): FlowControlledWalletV2 {
        return this.wallet;
    }

    /**
     * Add Flow account to monitoring
     */
    async addFlowAccountMonitoring(flowAddress: string): Promise<void> {
        await this.bundler.addFlowAccount(flowAddress);
    }

    /**
     * Remove Flow account from monitoring
     */
    async removeFlowAccountMonitoring(flowAddress: string): Promise<void> {
        await this.bundler.removeFlowAccount(flowAddress);
    }

    /**
     * Get Flow account monitoring state
     */
    async getFlowAccountState(flowAddress: string): Promise<FlowAccountMonitorV2> {
        return await this.bundler.getFlowAccountState(flowAddress);
    }

    /**
     * Get bundler statistics
     */
    async getBundlerStats(): Promise<BundlerStatsV2> {
        return await this.bundler.getBundlerStats();
    }
}