/**
 * @file flow-controlled-v2.ts
 * @description TypeScript interfaces for Flow-controlled ERC-4337 V2 implementation
 * Supports multi-signature operations with KeyInfo structures and CREATE2 deployment
 */

// KeyInfo structure matching the EVM contract
export interface KeyInfo {
    publicKey: string;          // 64 bytes hex, uncompressed, no 04 prefix
    weight: number;             // Flow key weight (0-1000)
    hashAlgorithm: number;      // Hash algorithm ID (1=SHA2_256, 2=SHA3_256)
    signatureAlgorithm: number; // Signature algorithm (1=ECDSA_P256, 2=ECDSA_secp256k1)
    isRevoked: boolean;         // Key revocation status
    keyIndex: number;           // Original Flow key index
}

// Flow native key structure (from Flow blockchain)
export interface FlowNativeKey {
    publicKey: {
        publicKey: string;      // Raw public key from Flow
    };
    weight: number;             // Weight as decimal (0.0-1.0)
    hashAlgorithm: number;      // Hash algorithm
    signatureAlgorithm: number; // Signature algorithm
    isRevoked: boolean;         // Revocation status
    keyIndex: number;           // Key index in Flow account
}

// Multi-signature user operation data structure
export interface FlowMultiSigUserOp {
    flowAddress: string;        // Flow account address
    opHash: string;             // keccak256(UserOperation)
    keys: KeyInfo[];            // Array of keys used for signing
    signatures: string[];       // Array of signatures corresponding to keys
    merkleProofs: string[][];   // Array of Merkle proofs for key inclusion
}

// Flow account state in EVM FlowKeyRegister
export interface FlowAccountState {
    keys: KeyInfo[];            // All keys for this Flow account
    totalWeight: number;        // Sum of all non-revoked key weights
    lastUpdateHeight: number;   // Flow block height when last updated
    lastUpdateTime: number;     // EVM timestamp when last updated
    lastUpdatedBy: string;      // Address that performed last update
    exists: boolean;            // Whether account is registered
}

// Merkle tree structure using KeyInfo hashes
export interface KeyInfoMerkleTree {
    root: string;               // Merkle root hash
    leaves: KeyInfoLeaf[];      // All leaves with KeyInfo hashes
    proofs: { [keyInfoHash: string]: string[] }; // Proofs for each KeyInfo hash
    totalKeys: number;          // Total number of keys
    blockHeight: number;        // Flow block height when built
    flowAddress: string;        // Flow account address
}

// Merkle tree leaf using KeyInfo hash
export interface KeyInfoLeaf {
    keyInfo: KeyInfo;           // Original KeyInfo
    keyInfoHash: string;        // keccak256(abi.encode(KeyInfo))
    leafIndex: number;          // Position in Merkle tree
}

// Bundler configuration for V2
export interface BundlerConfigV2 {
    flowEndpoint: string;       // Flow blockchain RPC endpoint
    evmEndpoint: string;        // EVM blockchain RPC endpoint
    flowKeyRegisterAddress: string; // EVM FlowKeyRegister contract address
    flowRootRegistryAddress: string; // EVM root registry contract address
    bundlerPrivateKey: string;  // Bundler private key for transactions
    pollingInterval: number;    // Polling interval in milliseconds
    maxRootAge: number;         // Maximum root age in seconds
    batchSize: number;          // Batch size for processing
    maxKeysPerUpdate: number;   // Maximum keys per account update
}

// Key mismatch detection result
export interface KeyMismatchResult {
    hasMismatch: boolean;       // Whether keys differ
    flowKeys: KeyInfo[];        // Current keys from Flow blockchain
    evmKeys: KeyInfo[];         // Current keys from EVM register
    differences: KeyDifference[]; // Specific differences found
    needsUpdate: boolean;       // Whether update is required
}

// Key difference details
export interface KeyDifference {
    type: 'added' | 'removed' | 'modified' | 'revoked';
    keyIndex: number;           // Flow key index
    flowKey?: KeyInfo;          // Key data from Flow (if exists)
    evmKey?: KeyInfo;           // Key data from EVM (if exists)
    description: string;        // Human-readable description
}

// Multi-signature creation request
export interface MultiSigRequest {
    flowAddress: string;        // Flow account address
    opHash: string;             // Operation hash to sign
    keySelectionStrategy: KeySelectionStrategy; // How to select keys
    minimumWeight?: number;     // Minimum weight (default: 1000)
    preferredAlgorithm?: SignatureAlgorithm; // Preferred signature algorithm
}

// Key selection strategy for multi-sig
export enum KeySelectionStrategy {
    ALL_AVAILABLE = 'all_available',           // Use all available keys
    MINIMUM_WEIGHT = 'minimum_weight',         // Use minimum keys to reach threshold
    PREFERRED_ALGORITHM = 'preferred_algorithm', // Prefer specific algorithm
    SPECIFIC_KEYS = 'specific_keys',           // Use specific key indices
    HIGHEST_WEIGHT = 'highest_weight'          // Use highest weight keys first
}

// Multi-signature creation response
export interface MultiSigResponse {
    userOp: FlowMultiSigUserOp; // Complete user operation with proofs
    totalWeight: number;        // Total weight of selected keys
    keyCount: number;           // Number of keys used
    usedAlgorithms: SignatureAlgorithm[]; // Algorithms used
}

// Factory deployment configuration
export interface FactoryDeployment {
    factoryAddress: string;     // CREATE2 factory address
    implementationAddress: string; // Smart account implementation
    predictedAddress: string;   // Predicted account address
    salt: string;               // CREATE2 salt used
    initCode: string;           // Initialization code
}

// Account creation request
export interface AccountCreationRequest {
    flowAddress: string;        // Flow account to link
    deployImmediately?: boolean; // Whether to deploy now or predict address
    initialKeySync?: boolean;   // Whether to sync keys immediately
}

// Account creation response
export interface AccountCreationResponse {
    smartAccountAddress: string; // Deployed/predicted smart account address
    flowAddress: string;        // Linked Flow address
    transactionHash?: string;   // Deployment transaction hash (if deployed)
    isDeployed: boolean;        // Whether account is deployed
    initialKeyCount?: number;   // Number of keys synced (if sync enabled)
}

// Bundler statistics for V2
export interface BundlerStatsV2 {
    totalFlowAccounts: number;  // Total monitored Flow accounts
    totalKeyUpdates: number;    // Total key updates performed
    totalRootUpdates: number;   // Total root updates
    totalUserOpsProcessed: number; // Total user operations processed
    averageKeyCount: number;    // Average keys per Flow account
    lastSyncTime: number;       // Last synchronization timestamp
    uptime: number;             // Bundler uptime in milliseconds
    errorCount: number;         // Total errors encountered
    mismatchesDetected: number; // Total key mismatches detected
    averageProcessingTime: number; // Average operation processing time
}

// Flow account monitoring data for V2
export interface FlowAccountMonitorV2 {
    address: string;            // Flow account address
    lastBlockHeight: number;    // Last processed Flow block height
    lastKeyUpdateTime: number;  // Last key update timestamp
    currentKeyCount: number;    // Current number of keys
    totalWeight: number;        // Total weight of active keys
    lastMismatchCheck: number;  // Last mismatch check timestamp
    smartAccountAddress?: string; // Associated smart account address
    isActive: boolean;          // Whether account is being monitored
    hasSmartAccount: boolean;   // Whether smart account is deployed
}

// Signature algorithms (updated)
export enum SignatureAlgorithm {
    ECDSA_P256 = 1,
    ECDSA_secp256k1 = 2
}

// Hash algorithms
export enum HashAlgorithm {
    SHA2_256 = 1,
    SHA3_256 = 2
}

// User operation execution request for V2
export interface UserOpExecutionRequestV2 {
    multiSigUserOp: FlowMultiSigUserOp; // Multi-signature user operation
    target: string;             // Target contract address
    data: string;               // Call data (hex)
    value: string;              // ETH value to send (wei)
    gasLimit: string;           // Gas limit
    gasPrice?: string;          // Gas price (optional)
}

// Batch execution request
export interface BatchExecutionRequest {
    userOps: FlowMultiSigUserOp[]; // Array of multi-sig user operations
    targets: string[];          // Array of target addresses
    datas: string[];            // Array of call data
    values: string[];           // Array of ETH values
    gasLimits: string[];        // Array of gas limits
    gasPrice?: string;          // Gas price for all operations
}

// Flow wallet integration for V2
export interface FlowWalletV2 {
    authenticate(): Promise<string>; // Returns Flow address
    disconnect(): Promise<void>;
    isAuthenticated(): boolean;
    getCurrentAddress(): string | null;
    getAvailableKeys(): Promise<KeyInfo[]>;
    signMultiSig(request: MultiSigRequest): Promise<MultiSigResponse>;
    selectKeys(strategy: KeySelectionStrategy, options?: any): Promise<KeyInfo[]>;
    createUserOperation(
        target: string,
        data: string,
        value?: string,
        options?: {
            keySelection?: KeySelectionStrategy;
            minimumWeight?: number;
            gasLimit?: string;
        }
    ): Promise<FlowMultiSigUserOp>;
}

// Bundler service interface for V2
export interface IBundlerServiceV2 {
    // Core functionality
    start(): Promise<void>;
    stop(): Promise<void>;
    
    // Flow monitoring
    addFlowAccount(address: string): Promise<void>;
    removeFlowAccount(address: string): Promise<void>;
    checkKeyMismatch(flowAddress: string): Promise<KeyMismatchResult>;
    syncKeys(flowAddress: string): Promise<boolean>;
    
    // Merkle tree operations
    buildKeyInfoMerkleTree(flowAddress: string): Promise<KeyInfoMerkleTree>;
    getKeyInfoProof(flowAddress: string, keyInfo: KeyInfo): Promise<string[]>;
    
    // Root management
    updateRoot(flowAddress: string, merkleTree: KeyInfoMerkleTree): Promise<string>;
    checkRootFreshness(flowAddress: string): Promise<boolean>;
    
    // Account management
    deployAccount(request: AccountCreationRequest): Promise<AccountCreationResponse>;
    predictAccountAddress(flowAddress: string): Promise<string>;
    
    // User operation processing
    processUserOp(request: UserOpExecutionRequestV2): Promise<string>;
    batchProcessUserOps(request: BatchExecutionRequest): Promise<string[]>;
    
    // State queries
    getFlowAccountState(address: string): Promise<FlowAccountMonitorV2>;
    getBundlerStats(): Promise<BundlerStatsV2>;
}

// Service configuration for V2
export interface FlowControlledServiceConfigV2 {
    bundler: BundlerConfigV2;
    factory: {
        factoryAddress: string;
        implementationAddress: string;
    };
    flowKeyRegister: string;
    rootRegistry: string;
}

// Error types for V2
export enum FlowControlledErrorV2 {
    INVALID_FLOW_ADDRESS = "INVALID_FLOW_ADDRESS",
    INVALID_KEY_INFO = "INVALID_KEY_INFO",
    INSUFFICIENT_SIGNATURE_WEIGHT = "INSUFFICIENT_SIGNATURE_WEIGHT",
    STALE_MERKLE_ROOT = "STALE_MERKLE_ROOT",
    INVALID_MERKLE_PROOF = "INVALID_MERKLE_PROOF",
    INVALID_MULTI_SIGNATURE = "INVALID_MULTI_SIGNATURE",
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM",
    OPERATION_ALREADY_EXECUTED = "OPERATION_ALREADY_EXECUTED",
    BUNDLER_NOT_AUTHORIZED = "BUNDLER_NOT_AUTHORIZED",
    FLOW_CHAIN_ERROR = "FLOW_CHAIN_ERROR",
    EVM_CHAIN_ERROR = "EVM_CHAIN_ERROR",
    KEY_MISMATCH_DETECTED = "KEY_MISMATCH_DETECTED",
    ACCOUNT_NOT_DEPLOYED = "ACCOUNT_NOT_DEPLOYED",
    FACTORY_DEPLOYMENT_FAILED = "FACTORY_DEPLOYMENT_FAILED",
    DUPLICATE_KEY_USAGE = "DUPLICATE_KEY_USAGE"
}

// Custom error class for V2
export class FlowControlledAccountErrorV2 extends Error {
    constructor(
        public code: FlowControlledErrorV2,
        message: string,
        public details?: any
    ) {
        super(message);
        this.name = "FlowControlledAccountErrorV2";
    }
}

// Utility types
export type HexString = string;
export type Address = string;
export type BlockHeight = number;
export type Timestamp = number;
export type Weight = number; // 0-1000 for Flow weights