/**
 * @file FlowControlledBundler.ts
 * @description Bundler for Flow-controlled ERC-4337 with multi-signature support
 * Monitors Flow blockchain and updates EVM FlowKeyRegister when keys mismatch
 */

import { ethers } from 'ethers';
import * as fcl from '@onflow/fcl';
import { MerkleTree as MerkleTreeJS } from 'merkletreejs';
import {
    KeyInfo,
    FlowNativeKey,
    FlowMultiSigUserOp,
    FlowAccountState,
    KeyInfoMerkleTree,
    KeyInfoLeaf,
    BundlerConfigV2,
    FlowAccountMonitorV2,
    KeyMismatchResult,
    KeyDifference,
    UserOpExecutionRequestV2,
    BatchExecutionRequest,
    BundlerStatsV2,
    AccountCreationRequest,
    AccountCreationResponse,
    IBundlerServiceV2,
    SignatureAlgorithm,
    HashAlgorithm,
    FlowControlledErrorV2,
    FlowControlledAccountErrorV2
} from '../types/flow-controlled-v2';

export class FlowControlledBundler implements IBundlerServiceV2 {
    private config: BundlerConfigV2;
    private evmProvider: ethers.providers.JsonRpcProvider;
    private bundlerWallet: ethers.Wallet;
    private flowKeyRegister: ethers.Contract;
    private flowRootRegistry: ethers.Contract;
    private accountFactory: ethers.Contract;
    private isRunning: boolean = false;
    private pollingTimer: NodeJS.Timeout | null = null;
    private stats: BundlerStatsV2;
    private monitoredAccounts: Map<string, FlowAccountMonitorV2>;

    constructor(config: BundlerConfigV2) {
        this.config = config;
        this.stats = {
            totalFlowAccounts: 0,
            totalKeyUpdates: 0,
            totalRootUpdates: 0,
            totalUserOpsProcessed: 0,
            averageKeyCount: 0,
            lastSyncTime: 0,
            uptime: Date.now(),
            errorCount: 0,
            mismatchesDetected: 0,
            averageProcessingTime: 0
        };
        this.monitoredAccounts = new Map();
        this.initializeProviders();
    }

    private initializeProviders() {
        // Initialize Flow provider
        fcl.config({
            'accessNode.api': this.config.flowEndpoint
        });

        // Initialize EVM provider
        this.evmProvider = new ethers.providers.JsonRpcProvider(this.config.evmEndpoint);
        this.bundlerWallet = new ethers.Wallet(this.config.bundlerPrivateKey, this.evmProvider);

        // Initialize contract interfaces
        this.initializeContracts();
    }

    private initializeContracts() {
        // FlowKeyRegister ABI
        const keyRegisterABI = [
            "function updateKeys(address flowAddress, tuple(bytes publicKey, uint256 weight, uint8 hashAlgorithm, uint8 signatureAlgorithm, bool isRevoked, uint256 keyIndex)[] keys, uint256 blockHeight) external",
            "function getKeys(address flowAddress) external view returns (tuple(bytes publicKey, uint256 weight, uint8 hashAlgorithm, uint8 signatureAlgorithm, bool isRevoked, uint256 keyIndex)[])",
            "function getAccountState(address flowAddress) external view returns (uint256 keyCount, uint256 totalWeight, uint256 lastUpdateHeight, uint256 lastUpdateTime, bool exists)",
            "function createKeyInfoHash(tuple(bytes publicKey, uint256 weight, uint8 hashAlgorithm, uint8 signatureAlgorithm, bool isRevoked, uint256 keyIndex) keyInfo) external pure returns (bytes32)",
            "function getKeyInfoHashes(address flowAddress) external view returns (bytes32[])"
        ];

        // FlowRootRegistry ABI
        const rootRegistryABI = [
            "function updateRoot(address flowAddress, bytes32 root, uint256 height, uint256 keyCount) external",
            "function getRoot(address flowAddress) external view returns (bytes32)",
            "function isRootFresh(address flowAddress) external view returns (bool)",
            "function verifyMerkleProof(bytes32 leaf, bytes32[] proof, bytes32 root) external pure returns (bool)"
        ];

        // Account Factory ABI
        const factoryABI = [
            "function createAccount(address flowAddress) external returns (address)",
            "function getAddress(address flowAddress) external view returns (address)",
            "function accountExists(address flowAddress) external view returns (bool)"
        ];

        this.flowKeyRegister = new ethers.Contract(
            this.config.flowKeyRegisterAddress,
            keyRegisterABI,
            this.bundlerWallet
        );

        this.flowRootRegistry = new ethers.Contract(
            this.config.flowRootRegistryAddress,
            rootRegistryABI,
            this.bundlerWallet
        );

        // Factory address would come from config
        // this.accountFactory = new ethers.Contract(factoryAddress, factoryABI, this.bundlerWallet);
    }

    async start(): Promise<void> {
        if (this.isRunning) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.BUNDLER_NOT_AUTHORIZED,
                "Bundler is already running"
            );
        }

        console.log("Starting Flow-controlled bundler V2...");
        this.isRunning = true;
        this.stats.uptime = Date.now();
        
        this.startPolling();
        console.log("Bundler V2 started successfully");
    }

    async stop(): Promise<void> {
        if (!this.isRunning) return;

        console.log("Stopping Flow-controlled bundler V2...");
        this.isRunning = false;
        
        if (this.pollingTimer) {
            clearInterval(this.pollingTimer);
            this.pollingTimer = null;
        }
        
        console.log("Bundler V2 stopped");
    }

    private startPolling() {
        this.pollingTimer = setInterval(async () => {
            try {
                await this.pollAllFlowAccounts();
            } catch (error) {
                console.error("Polling error:", error);
                this.stats.errorCount++;
            }
        }, this.config.pollingInterval);
    }

    private async pollAllFlowAccounts() {
        const startTime = Date.now();
        
        for (const [flowAddress, monitor] of this.monitoredAccounts) {
            try {
                const mismatchResult = await this.checkKeyMismatch(flowAddress);
                
                if (mismatchResult.needsUpdate) {
                    console.log(`Key mismatch detected for ${flowAddress}, updating...`);
                    await this.syncKeys(flowAddress);
                    this.stats.mismatchesDetected++;
                }
                
                monitor.lastMismatchCheck = Date.now();
            } catch (error) {
                console.error(`Error checking Flow account ${flowAddress}:`, error);
                this.stats.errorCount++;
            }
        }
        
        this.stats.lastSyncTime = Date.now();
        const processingTime = Date.now() - startTime;
        this.stats.averageProcessingTime = (this.stats.averageProcessingTime + processingTime) / 2;
    }

    async addFlowAccount(address: string): Promise<void> {
        if (!ethers.utils.isAddress(address)) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                `Invalid Flow address: ${address}`
            );
        }

        const monitor: FlowAccountMonitorV2 = {
            address,
            lastBlockHeight: 0,
            lastKeyUpdateTime: 0,
            currentKeyCount: 0,
            totalWeight: 0,
            lastMismatchCheck: 0,
            isActive: true,
            hasSmartAccount: false
        };

        this.monitoredAccounts.set(address, monitor);
        this.stats.totalFlowAccounts = this.monitoredAccounts.size;
        
        console.log(`Added Flow account for monitoring: ${address}`);
        
        // Immediately check and sync keys
        await this.syncKeys(address);
    }

    async removeFlowAccount(address: string): Promise<void> {
        this.monitoredAccounts.delete(address);
        this.stats.totalFlowAccounts = this.monitoredAccounts.size;
        console.log(`Removed Flow account from monitoring: ${address}`);
    }

    async checkKeyMismatch(flowAddress: string): Promise<KeyMismatchResult> {
        try {
            // Get keys from Flow blockchain
            const flowKeys = await this.fetchFlowNativeKeys(flowAddress);
            
            // Get keys from EVM FlowKeyRegister
            let evmKeys: KeyInfo[] = [];
            try {
                evmKeys = await this.flowKeyRegister.getKeys(flowAddress);
            } catch (error) {
                // Account might not be registered yet
                console.log(`Account ${flowAddress} not registered in EVM, needs initial sync`);
            }

            // Compare keys
            const differences = this.compareKeys(flowKeys, evmKeys);
            const hasMismatch = differences.length > 0;
            const needsUpdate = hasMismatch || evmKeys.length === 0;

            return {
                hasMismatch,
                flowKeys,
                evmKeys,
                differences,
                needsUpdate
            };
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.KEY_MISMATCH_DETECTED,
                `Failed to check key mismatch for ${flowAddress}`,
                error
            );
        }
    }

    private async fetchFlowNativeKeys(flowAddress: string): Promise<KeyInfo[]> {
        const script = `
            pub fun main(account: Address): [AnyStruct] {
                let accountRef = getAccount(account)
                let keys: [AnyStruct] = []
                
                for keyIndex in accountRef.keys.keys {
                    if let key = accountRef.keys.get(keyIndex: keyIndex) {
                        // Only include supported algorithms (ECDSA_P256=1, ECDSA_secp256k1=2)
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
                args: (arg: any, t: any) => [arg(flowAddress, t.Address)]
            });

            return result.map((keyData: any) => this.convertFlowKeyToKeyInfo(keyData));
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.FLOW_CHAIN_ERROR,
                `Failed to fetch Flow native keys for ${flowAddress}`,
                error
            );
        }
    }

    private convertFlowKeyToKeyInfo(flowKeyData: any): KeyInfo {
        // Convert Flow's public key format
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

    private compareKeys(flowKeys: KeyInfo[], evmKeys: KeyInfo[]): KeyDifference[] {
        const differences: KeyDifference[] = [];
        
        // Create maps for easier comparison
        const flowKeyMap = new Map(flowKeys.map(k => [k.keyIndex, k]));
        const evmKeyMap = new Map(evmKeys.map(k => [k.keyIndex, k]));

        // Check for added or modified keys
        for (const flowKey of flowKeys) {
            const evmKey = evmKeyMap.get(flowKey.keyIndex);
            
            if (!evmKey) {
                differences.push({
                    type: 'added',
                    keyIndex: flowKey.keyIndex,
                    flowKey,
                    description: `Key ${flowKey.keyIndex} added to Flow account`
                });
            } else if (!this.keysEqual(flowKey, evmKey)) {
                differences.push({
                    type: 'modified',
                    keyIndex: flowKey.keyIndex,
                    flowKey,
                    evmKey,
                    description: `Key ${flowKey.keyIndex} modified`
                });
            }
        }

        // Check for removed keys
        for (const evmKey of evmKeys) {
            if (!flowKeyMap.has(evmKey.keyIndex)) {
                differences.push({
                    type: 'removed',
                    keyIndex: evmKey.keyIndex,
                    evmKey,
                    description: `Key ${evmKey.keyIndex} removed from Flow account`
                });
            }
        }

        return differences;
    }

    private keysEqual(key1: KeyInfo, key2: KeyInfo): boolean {
        return (
            key1.publicKey === key2.publicKey &&
            key1.weight === key2.weight &&
            key1.hashAlgorithm === key2.hashAlgorithm &&
            key1.signatureAlgorithm === key2.signatureAlgorithm &&
            key1.isRevoked === key2.isRevoked &&
            key1.keyIndex === key2.keyIndex
        );
    }

    async syncKeys(flowAddress: string): Promise<boolean> {
        try {
            const mismatchResult = await this.checkKeyMismatch(flowAddress);
            
            if (!mismatchResult.needsUpdate) {
                return false; // No update needed
            }

            // Get current Flow block height
            const blockHeight = await this.getCurrentFlowBlockHeight();

            // Update keys in EVM FlowKeyRegister
            const tx = await this.flowKeyRegister.updateKeys(
                flowAddress,
                mismatchResult.flowKeys,
                blockHeight,
                {
                    gasLimit: 500000,
                    gasPrice: await this.evmProvider.getGasPrice()
                }
            );

            await tx.wait();
            
            // Update Merkle root
            const merkleTree = await this.buildKeyInfoMerkleTree(flowAddress);
            await this.updateRoot(flowAddress, merkleTree);

            // Update monitoring data
            const monitor = this.monitoredAccounts.get(flowAddress);
            if (monitor) {
                monitor.lastKeyUpdateTime = Date.now();
                monitor.currentKeyCount = mismatchResult.flowKeys.length;
                monitor.totalWeight = mismatchResult.flowKeys
                    .filter(k => !k.isRevoked)
                    .reduce((sum, k) => sum + k.weight, 0);
                monitor.lastBlockHeight = blockHeight;
            }

            this.stats.totalKeyUpdates++;
            console.log(`Successfully synced keys for ${flowAddress}`);
            return true;
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.EVM_CHAIN_ERROR,
                `Failed to sync keys for ${flowAddress}`,
                error
            );
        }
    }

    private async getCurrentFlowBlockHeight(): Promise<number> {
        const script = `
            pub fun main(): UInt64 {
                return getCurrentBlock().height
            }
        `;

        const result = await fcl.query({ cadence: script });
        return parseInt(result);
    }

    async buildKeyInfoMerkleTree(flowAddress: string): Promise<KeyInfoMerkleTree> {
        try {
            const keys = await this.flowKeyRegister.getKeys(flowAddress);
            
            if (keys.length === 0) {
                throw new FlowControlledAccountErrorV2(
                    FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                    `No keys found for Flow address: ${flowAddress}`
                );
            }

            // Sort keys by keyIndex to maintain order
            const sortedKeys = keys.sort((a: KeyInfo, b: KeyInfo) => a.keyIndex - b.keyIndex);

            // Create KeyInfo hashes for leaves
            const leaves: KeyInfoLeaf[] = sortedKeys.map((keyInfo: KeyInfo, index: number) => {
                const keyInfoHash = ethers.utils.keccak256(
                    ethers.utils.defaultAbiCoder.encode(
                        ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                        [
                            keyInfo.publicKey,
                            keyInfo.weight,
                            keyInfo.hashAlgorithm,
                            keyInfo.signatureAlgorithm,
                            keyInfo.isRevoked,
                            keyInfo.keyIndex
                        ]
                    )
                );

                return {
                    keyInfo,
                    keyInfoHash,
                    leafIndex: index
                };
            });

            // Build Merkle tree
            const leafHashes = leaves.map(leaf => leaf.keyInfoHash);
            const tree = new MerkleTreeJS(leafHashes, ethers.utils.keccak256, {
                sortPairs: true,
                duplicateOdd: true
            });

            // Generate proofs for all leaves
            const proofs: { [keyInfoHash: string]: string[] } = {};
            leaves.forEach(leaf => {
                const proof = tree.getHexProof(leaf.keyInfoHash);
                proofs[leaf.keyInfoHash] = proof;
            });

            return {
                root: tree.getHexRoot(),
                leaves,
                proofs,
                totalKeys: leaves.length,
                blockHeight: await this.getCurrentFlowBlockHeight(),
                flowAddress
            };
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.EVM_CHAIN_ERROR,
                `Failed to build Merkle tree for ${flowAddress}`,
                error
            );
        }
    }

    async getKeyInfoProof(flowAddress: string, keyInfo: KeyInfo): Promise<string[]> {
        const merkleTree = await this.buildKeyInfoMerkleTree(flowAddress);
        
        const keyInfoHash = ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                [
                    keyInfo.publicKey,
                    keyInfo.weight,
                    keyInfo.hashAlgorithm,
                    keyInfo.signatureAlgorithm,
                    keyInfo.isRevoked,
                    keyInfo.keyIndex
                ]
            )
        );

        const proof = merkleTree.proofs[keyInfoHash];
        if (!proof) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_KEY_INFO,
                `KeyInfo not found in Merkle tree for ${flowAddress}`
            );
        }

        return proof;
    }

    async updateRoot(flowAddress: string, merkleTree: KeyInfoMerkleTree): Promise<string> {
        try {
            const tx = await this.flowRootRegistry.updateRoot(
                flowAddress,
                merkleTree.root,
                merkleTree.blockHeight,
                merkleTree.totalKeys,
                {
                    gasLimit: 200000,
                    gasPrice: await this.evmProvider.getGasPrice()
                }
            );

            await tx.wait();
            this.stats.totalRootUpdates++;
            
            console.log(`Updated root for ${flowAddress}: ${merkleTree.root}`);
            return tx.hash;
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.EVM_CHAIN_ERROR,
                `Failed to update root for ${flowAddress}`,
                error
            );
        }
    }

    async checkRootFreshness(flowAddress: string): Promise<boolean> {
        try {
            return await this.flowRootRegistry.isRootFresh(flowAddress);
        } catch (error) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.EVM_CHAIN_ERROR,
                `Failed to check root freshness for ${flowAddress}`,
                error
            );
        }
    }

    async deployAccount(request: AccountCreationRequest): Promise<AccountCreationResponse> {
        // This would use the account factory
        // Implementation depends on factory contract deployment
        throw new Error("Account deployment not implemented - requires factory contract");
    }

    async predictAccountAddress(flowAddress: string): Promise<string> {
        // This would use the account factory
        // Implementation depends on factory contract deployment
        throw new Error("Address prediction not implemented - requires factory contract");
    }

    async processUserOp(request: UserOpExecutionRequestV2): Promise<string> {
        // Placeholder for ERC-4337 EntryPoint integration
        this.stats.totalUserOpsProcessed++;
        return "0x" + Buffer.from(Math.random().toString()).toString('hex');
    }

    async batchProcessUserOps(request: BatchExecutionRequest): Promise<string[]> {
        const results = [];
        for (let i = 0; i < request.userOps.length; i++) {
            const singleRequest: UserOpExecutionRequestV2 = {
                multiSigUserOp: request.userOps[i],
                target: request.targets[i],
                data: request.datas[i],
                value: request.values[i],
                gasLimit: request.gasLimits[i],
                gasPrice: request.gasPrice
            };
            results.push(await this.processUserOp(singleRequest));
        }
        return results;
    }

    async getFlowAccountState(address: string): Promise<FlowAccountMonitorV2> {
        const monitor = this.monitoredAccounts.get(address);
        if (!monitor) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                `Flow address not monitored: ${address}`
            );
        }
        return monitor;
    }

    async getBundlerStats(): Promise<BundlerStatsV2> {
        // Calculate average key count
        let totalKeys = 0;
        for (const monitor of this.monitoredAccounts.values()) {
            totalKeys += monitor.currentKeyCount;
        }
        
        this.stats.averageKeyCount = this.monitoredAccounts.size > 0 ? 
            totalKeys / this.monitoredAccounts.size : 0;

        return {
            ...this.stats,
            uptime: Date.now() - this.stats.uptime
        };
    }
}