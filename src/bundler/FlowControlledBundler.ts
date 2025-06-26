/**
 * @file FlowControlledBundler.ts
 * @description Bundler service for Flow-controlled ERC-4337 accounts
 * Handles Flow key monitoring, Merkle tree construction, and root synchronization
 */

import { ethers } from 'ethers';
import * as fcl from '@onflow/fcl';
import { MerkleTree as MerkleTreeJS } from 'merkletreejs';
import crypto from 'crypto';
import {
    FlowKey,
    FlowKeyRegistryResponse,
    MerkleTree,
    MerkleLeaf,
    RootUpdate,
    BundlerConfig,
    BundlerState,
    FlowAccountMonitor,
    FlowControlledUserOp,
    UserOpExecutionRequest,
    BundlerStats,
    IBundlerService,
    SignatureAlgorithm,
    HashAlgorithm,
    FlowControlledError,
    FlowControlledAccountError
} from '../types/flow-controlled';

export class FlowControlledBundler implements IBundlerService {
    private config: BundlerConfig;
    private state: BundlerState;
    private flowProvider: any;
    private evmProvider: ethers.providers.JsonRpcProvider;
    private bundlerWallet: ethers.Wallet;
    private flowRootRegistry: ethers.Contract;
    private isRunning: boolean = false;
    private pollingTimer: NodeJS.Timeout | null = null;
    private stats: BundlerStats;

    constructor(config: BundlerConfig) {
        this.config = config;
        this.state = {
            lastProcessedHeight: {},
            pendingUpdates: [],
            activeFlowAccounts: new Set(),
            merkleTreeCache: {},
            lastSyncTime: 0
        };
        
        this.stats = {
            totalFlowAccounts: 0,
            totalRootUpdates: 0,
            totalUserOpsProcessed: 0,
            lastSyncTime: 0,
            uptime: Date.now(),
            errorCount: 0,
            averageProcessingTime: 0
        };

        this.initializeProviders();
    }

    private initializeProviders() {
        // Initialize Flow provider
        fcl.config({
            'accessNode.api': this.config.flowEndpoint,
            'discovery.wallet': 'https://fcl-discovery.onflow.org/testnet/authn'
        });

        // Initialize EVM provider
        this.evmProvider = new ethers.providers.JsonRpcProvider(this.config.evmEndpoint);
        this.bundlerWallet = new ethers.Wallet(this.config.bundlerPrivateKey, this.evmProvider);

        // Initialize FlowRootRegistry contract
        const registryABI = [
            "function updateRoot(address flowAddress, bytes32 root, uint256 height, uint256 keyCount) external",
            "function getRoot(address flowAddress) external view returns (bytes32)",
            "function getRootData(address flowAddress) external view returns (tuple(bytes32 merkleRoot, uint256 lastUpdateHeight, uint256 lastUpdateTime, uint256 keyCount, address updatedBy))",
            "function isRootFresh(address flowAddress) external view returns (bool)",
            "function verifyMerkleProof(bytes32 leaf, bytes32[] memory proof, bytes32 root) external pure returns (bool)",
            "function createLeafHash(bytes memory publicKey, uint256 weight, uint8 hashAlgorithm, uint8 signatureAlgorithm) external pure returns (bytes32)"
        ];

        this.flowRootRegistry = new ethers.Contract(
            this.config.flowRootRegistryAddress,
            registryABI,
            this.bundlerWallet
        );
    }

    async start(): Promise<void> {
        if (this.isRunning) {
            throw new FlowControlledAccountError(
                FlowControlledError.BUNDLER_NOT_AUTHORIZED,
                "Bundler is already running"
            );
        }

        console.log("Starting Flow-controlled bundler...");
        this.isRunning = true;
        this.stats.uptime = Date.now();
        
        // Start polling for Flow key updates
        this.startPolling();
        
        console.log("Bundler started successfully");
    }

    async stop(): Promise<void> {
        if (!this.isRunning) return;

        console.log("Stopping Flow-controlled bundler...");
        this.isRunning = false;
        
        if (this.pollingTimer) {
            clearInterval(this.pollingTimer);
            this.pollingTimer = null;
        }
        
        console.log("Bundler stopped");
    }

    private startPolling() {
        this.pollingTimer = setInterval(async () => {
            try {
                await this.pollFlowAccounts();
            } catch (error) {
                console.error("Polling error:", error);
                this.stats.errorCount++;
            }
        }, this.config.pollingInterval);
    }

    private async pollFlowAccounts() {
        const startTime = Date.now();
        
        for (const flowAddress of this.state.activeFlowAccounts) {
            try {
                await this.checkAndUpdateFlowAccount(flowAddress);
            } catch (error) {
                console.error(`Error updating Flow account ${flowAddress}:`, error);
                this.stats.errorCount++;
            }
        }
        
        this.state.lastSyncTime = Date.now();
        this.stats.lastSyncTime = this.state.lastSyncTime;
        
        const processingTime = Date.now() - startTime;
        this.stats.averageProcessingTime = 
            (this.stats.averageProcessingTime + processingTime) / 2;
    }

    async addFlowAccount(address: string): Promise<void> {
        if (!ethers.utils.isAddress(address)) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                `Invalid Flow address: ${address}`
            );
        }

        this.state.activeFlowAccounts.add(address);
        this.state.lastProcessedHeight[address] = 0;
        this.stats.totalFlowAccounts = this.state.activeFlowAccounts.size;
        
        console.log(`Added Flow account for monitoring: ${address}`);
        
        // Immediately check for updates
        await this.checkAndUpdateFlowAccount(address);
    }

    async removeFlowAccount(address: string): Promise<void> {
        this.state.activeFlowAccounts.delete(address);
        delete this.state.lastProcessedHeight[address];
        delete this.state.merkleTreeCache[address];
        this.stats.totalFlowAccounts = this.state.activeFlowAccounts.size;
        
        console.log(`Removed Flow account from monitoring: ${address}`);
    }

    private async checkAndUpdateFlowAccount(flowAddress: string) {
        // Fetch current keys from Flow
        const keyResponse = await this.fetchFlowKeys(flowAddress);
        
        // Check if update is needed
        const lastHeight = this.state.lastProcessedHeight[flowAddress] || 0;
        if (keyResponse.blockHeight <= lastHeight) {
            return; // No new updates
        }

        // Build new Merkle tree
        const merkleTree = await this.buildMerkleTreeFromKeys(flowAddress, keyResponse.keys, keyResponse.blockHeight);
        
        // Check if root changed
        const currentRoot = await this.flowRootRegistry.getRoot(flowAddress);
        if (currentRoot === merkleTree.root) {
            // Root unchanged, just update cache
            this.state.merkleTreeCache[flowAddress] = merkleTree;
            this.state.lastProcessedHeight[flowAddress] = keyResponse.blockHeight;
            return;
        }

        // Root changed, update registry
        const update: RootUpdate = {
            flowAddress,
            merkleRoot: merkleTree.root,
            blockHeight: keyResponse.blockHeight,
            keyCount: keyResponse.keys.length,
            timestamp: Date.now()
        };

        await this.updateRoot(update);
        
        // Update cache and state
        this.state.merkleTreeCache[flowAddress] = merkleTree;
        this.state.lastProcessedHeight[flowAddress] = keyResponse.blockHeight;
    }

    private async fetchFlowKeys(flowAddress: string): Promise<FlowKeyRegistryResponse> {
        const script = `
            import FlowKeyRegister from ${this.config.flowKeyRegisterAddress}
            
            pub fun main(account: Address): FlowKeyRegister.FlowKeyRegistryResponse {
                let keys = FlowKeyRegister.getKeys(account: account)
                let blockHeight = FlowKeyRegister.getCurrentBlockHeight()
                
                return FlowKeyRegister.FlowKeyRegistryResponse(
                    keys: keys,
                    blockHeight: blockHeight,
                    account: account,
                    timestamp: getCurrentBlock().timestamp
                )
            }
        `;

        try {
            const result = await fcl.query({
                cadence: script,
                args: (arg: any, t: any) => [arg(flowAddress, t.Address)]
            });

            return {
                keys: result.keys.map((key: any) => ({
                    publicKey: key.publicKey,
                    weight: parseFloat(key.weight),
                    hashAlgorithm: parseInt(key.hashAlgorithm),
                    signatureAlgorithm: parseInt(key.signatureAlgorithm),
                    isRevoked: key.isRevoked,
                    keyIndex: parseInt(key.keyIndex)
                })),
                blockHeight: parseInt(result.blockHeight),
                account: result.account,
                timestamp: parseInt(result.timestamp)
            };
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.FLOW_CHAIN_ERROR,
                `Failed to fetch Flow keys for ${flowAddress}`,
                error
            );
        }
    }

    async buildMerkleTree(flowAddress: string): Promise<MerkleTree> {
        const keyResponse = await this.fetchFlowKeys(flowAddress);
        return this.buildMerkleTreeFromKeys(flowAddress, keyResponse.keys, keyResponse.blockHeight);
    }

    private async buildMerkleTreeFromKeys(
        flowAddress: string,
        keys: FlowKey[],
        blockHeight: number
    ): Promise<MerkleTree> {
        if (keys.length === 0) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                `No active keys found for Flow address: ${flowAddress}`
            );
        }

        // Sort keys by keyIndex to maintain Flow account order
        const sortedKeys = keys.sort((a, b) => a.keyIndex - b.keyIndex);

        // Create leaves
        const leaves: MerkleLeaf[] = sortedKeys.map(key => {
            const publicKeyBytes = Buffer.from(key.publicKey, 'hex');
            const leafHash = ethers.utils.keccak256(
                ethers.utils.defaultAbiCoder.encode(
                    ['bytes', 'uint256', 'uint8', 'uint8'],
                    [publicKeyBytes, Math.floor(key.weight * 1000), key.hashAlgorithm, key.signatureAlgorithm]
                )
            );

            return {
                publicKey: key.publicKey,
                weight: key.weight,
                hashAlgorithm: key.hashAlgorithm,
                signatureAlgorithm: key.signatureAlgorithm,
                keyIndex: key.keyIndex,
                leafHash
            };
        });

        // Build Merkle tree
        const leafHashes = leaves.map(leaf => leaf.leafHash);
        const tree = new MerkleTreeJS(leafHashes, ethers.utils.keccak256, {
            sortPairs: true,
            duplicateOdd: true
        });

        // Generate proofs for all leaves
        const proofs: { [leafHash: string]: string[] } = {};
        leaves.forEach(leaf => {
            const proof = tree.getHexProof(leaf.leafHash);
            proofs[leaf.leafHash] = proof;
        });

        return {
            root: tree.getHexRoot(),
            leaves,
            proofs,
            totalKeys: leaves.length,
            blockHeight,
            flowAddress
        };
    }

    async getMerkleProof(flowAddress: string, publicKey: string): Promise<string[]> {
        const merkleTree = this.state.merkleTreeCache[flowAddress];
        if (!merkleTree) {
            throw new FlowControlledAccountError(
                FlowControlledError.STALE_MERKLE_ROOT,
                `No cached Merkle tree for Flow address: ${flowAddress}`
            );
        }

        const leaf = merkleTree.leaves.find(l => l.publicKey === publicKey);
        if (!leaf) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_PUBLIC_KEY,
                `Public key not found in Merkle tree: ${publicKey}`
            );
        }

        return merkleTree.proofs[leaf.leafHash];
    }

    async updateRoot(update: RootUpdate): Promise<string> {
        try {
            const tx = await this.flowRootRegistry.updateRoot(
                update.flowAddress,
                update.merkleRoot,
                update.blockHeight,
                update.keyCount,
                {
                    gasLimit: 200000,
                    gasPrice: await this.evmProvider.getGasPrice()
                }
            );

            await tx.wait();
            this.stats.totalRootUpdates++;
            
            console.log(`Updated root for ${update.flowAddress}: ${update.merkleRoot}`);
            return tx.hash;
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.EVM_CHAIN_ERROR,
                `Failed to update root for ${update.flowAddress}`,
                error
            );
        }
    }

    async checkRootFreshness(flowAddress: string): Promise<boolean> {
        try {
            return await this.flowRootRegistry.isRootFresh(flowAddress);
        } catch (error) {
            throw new FlowControlledAccountError(
                FlowControlledError.EVM_CHAIN_ERROR,
                `Failed to check root freshness for ${flowAddress}`,
                error
            );
        }
    }

    async processUserOp(request: UserOpExecutionRequest): Promise<string> {
        // This would integrate with ERC-4337 EntryPoint
        // For now, return a placeholder
        this.stats.totalUserOpsProcessed++;
        return "0x" + crypto.randomBytes(32).toString('hex');
    }

    async batchProcessUserOps(requests: UserOpExecutionRequest[]): Promise<string[]> {
        const results = [];
        for (const request of requests) {
            results.push(await this.processUserOp(request));
        }
        return results;
    }

    async getFlowAccountState(address: string): Promise<FlowAccountMonitor> {
        const merkleTree = this.state.merkleTreeCache[address];
        const rootData = await this.flowRootRegistry.getRootData(address);
        
        return {
            address,
            lastBlockHeight: this.state.lastProcessedHeight[address] || 0,
            currentMerkleRoot: merkleTree?.root || ethers.constants.HashZero,
            keyCount: merkleTree?.totalKeys || 0,
            lastUpdate: this.state.lastSyncTime,
            isActive: this.state.activeFlowAccounts.has(address)
        };
    }

    async getBundlerStats(): Promise<BundlerStats> {
        return {
            ...this.stats,
            uptime: Date.now() - this.stats.uptime
        };
    }
}