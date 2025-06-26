/**
 * @file flow-controlled.ts
 * @description TypeScript interfaces for Flow-controlled ERC-4337 implementation
 */

// Flow key data structure matching the Flow chain representation
export interface FlowKey {
    publicKey: string;          // Hex-encoded, uncompressed, no 04 prefix
    weight: number;             // Key weight for multi-sig (1000 = 1.0)
    hashAlgorithm: number;      // Hash algorithm identifier (1=SHA2_256, 2=SHA3_256)
    signatureAlgorithm: number; // Signature algorithm (1=ECDSA_P256, 2=ECDSA_secp256k1)
    isRevoked: boolean;         // Key revocation status
    keyIndex: number;           // Original key index in Flow account
}

// Flow key registry response from Flow chain
export interface FlowKeyRegistryResponse {
    keys: FlowKey[];
    blockHeight: number;
    account: string;
    timestamp: number;
}

// Merkle tree leaf data structure
export interface MerkleLeaf {
    publicKey: string;          // Public key without 04 prefix
    weight: number;             // Key weight
    hashAlgorithm: number;      // Hash algorithm ID
    signatureAlgorithm: number; // Signature algorithm ID
    keyIndex: number;           // Original Flow key index
    leafHash: string;           // keccak256 hash of leaf data
}

// Merkle tree structure
export interface MerkleTree {
    root: string;               // Merkle root hash
    leaves: MerkleLeaf[];       // All leaves in the tree
    proofs: { [leafHash: string]: string[] }; // Proofs for each leaf
    totalKeys: number;          // Total number of keys
    blockHeight: number;        // Flow block height when built
    flowAddress: string;        // Flow account address
}

// User operation data structure for Flow-controlled accounts
export interface FlowControlledUserOp {
    flowAddress: string;        // Flow account address
    opHash: string;             // keccak256(UserOperation)
    publicKey: string;          // Uncompressed public key (64 bytes hex, no 04 prefix)
    weight: number;             // Key weight from Flow account
    hashAlgorithm: number;      // Hash algorithm ID
    signatureAlgorithm: number; // Signature algorithm ID
    signature: string;          // secp256k1 or P256 signature
    merkleProof: string[];      // Merkle proof for key inclusion
}

// Registry update payload for root synchronization
export interface RootUpdate {
    flowAddress: string;        // Flow account address
    merkleRoot: string;         // New Merkle root
    blockHeight: number;        // Flow block height
    keyCount: number;           // Number of keys in the tree
    timestamp: number;          // Update timestamp
}

// Bundler configuration
export interface BundlerConfig {
    flowEndpoint: string;       // Flow blockchain RPC endpoint
    evmEndpoint: string;        // EVM blockchain RPC endpoint
    flowKeyRegisterAddress: string; // Flow key register contract address
    flowRootRegistryAddress: string; // EVM root registry contract address
    bundlerPrivateKey: string;  // Bundler private key for transactions
    pollingInterval: number;    // Polling interval in milliseconds
    maxRootAge: number;         // Maximum root age in seconds
    batchSize: number;          // Batch size for processing
}

// Bundler state tracking
export interface BundlerState {
    lastProcessedHeight: { [flowAddress: string]: number };
    pendingUpdates: RootUpdate[];
    activeFlowAccounts: Set<string>;
    merkleTreeCache: { [flowAddress: string]: MerkleTree };
    lastSyncTime: number;
}

// Flow account monitoring data
export interface FlowAccountMonitor {
    address: string;            // Flow account address
    lastBlockHeight: number;    // Last processed block height
    currentMerkleRoot: string;  // Current Merkle root
    keyCount: number;           // Number of active keys
    lastUpdate: number;         // Last update timestamp
    isActive: boolean;          // Whether account is being monitored
}

// Signature algorithms supported
export enum SignatureAlgorithm {
    ECDSA_P256 = 1,
    ECDSA_secp256k1 = 2
}

// Hash algorithms supported
export enum HashAlgorithm {
    SHA2_256 = 1,
    SHA3_256 = 2
}

// Wallet signature request for Flow keys
export interface FlowSignatureRequest {
    flowAddress: string;        // Flow account address
    message: string;            // Message to sign (hex)
    keyIndex?: number;          // Specific key index to use (optional)
    signatureAlgorithm: SignatureAlgorithm; // Required signature algorithm
}

// Wallet signature response
export interface FlowSignatureResponse {
    signature: string;          // Signature bytes (hex)
    publicKey: string;          // Public key used (64 bytes hex, no 04 prefix)
    keyIndex: number;           // Key index used
    weight: number;             // Key weight
    hashAlgorithm: number;      // Hash algorithm used
    signatureAlgorithm: number; // Signature algorithm used
}

// User operation execution request
export interface UserOpExecutionRequest {
    userOp: FlowControlledUserOp;
    target: string;             // Target contract address
    data: string;               // Call data (hex)
    value: string;              // ETH value to send (wei)
    gasLimit: string;           // Gas limit
    gasPrice: string;           // Gas price
}

// Bundler service interface
export interface IBundlerService {
    // Core functionality
    start(): Promise<void>;
    stop(): Promise<void>;
    
    // Flow monitoring
    addFlowAccount(address: string): Promise<void>;
    removeFlowAccount(address: string): Promise<void>;
    
    // Merkle tree operations
    buildMerkleTree(flowAddress: string): Promise<MerkleTree>;
    getMerkleProof(flowAddress: string, publicKey: string): Promise<string[]>;
    
    // Root management
    updateRoot(update: RootUpdate): Promise<string>; // Returns transaction hash
    checkRootFreshness(flowAddress: string): Promise<boolean>;
    
    // User operation processing
    processUserOp(request: UserOpExecutionRequest): Promise<string>; // Returns transaction hash
    batchProcessUserOps(requests: UserOpExecutionRequest[]): Promise<string[]>;
    
    // State queries
    getFlowAccountState(address: string): Promise<FlowAccountMonitor>;
    getBundlerStats(): Promise<BundlerStats>;
}

// Bundler statistics
export interface BundlerStats {
    totalFlowAccounts: number;
    totalRootUpdates: number;
    totalUserOpsProcessed: number;
    lastSyncTime: number;
    uptime: number;
    errorCount: number;
    averageProcessingTime: number;
}

// Error types for better error handling
export enum FlowControlledError {
    INVALID_FLOW_ADDRESS = "INVALID_FLOW_ADDRESS",
    INVALID_PUBLIC_KEY = "INVALID_PUBLIC_KEY",
    INSUFFICIENT_KEY_WEIGHT = "INSUFFICIENT_KEY_WEIGHT",
    STALE_MERKLE_ROOT = "STALE_MERKLE_ROOT",
    INVALID_MERKLE_PROOF = "INVALID_MERKLE_PROOF",
    INVALID_SIGNATURE = "INVALID_SIGNATURE",
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM",
    OPERATION_ALREADY_EXECUTED = "OPERATION_ALREADY_EXECUTED",
    BUNDLER_NOT_AUTHORIZED = "BUNDLER_NOT_AUTHORIZED",
    FLOW_CHAIN_ERROR = "FLOW_CHAIN_ERROR",
    EVM_CHAIN_ERROR = "EVM_CHAIN_ERROR"
}

// Custom error class
export class FlowControlledAccountError extends Error {
    constructor(
        public code: FlowControlledError,
        message: string,
        public details?: any
    ) {
        super(message);
        this.name = "FlowControlledAccountError";
    }
}

// Utility types
export type HexString = string;
export type Address = string;
export type BlockHeight = number;
export type Timestamp = number;