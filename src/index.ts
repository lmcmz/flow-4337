/**
 * @file index.ts
 * @description Main entry point for Flow-controlled ERC-4337 implementation
 * Exports core components for cross-chain account control via Merkle proofs
 */

// Core components
export { FlowControlledBundler } from './bundler/FlowControlledBundler';
export { FlowControlledWallet } from './wallet/FlowControlledWallet';

// Type definitions
export * from './types/flow-controlled';

// Utilities
export { FlowControlledService } from './services/FlowControlledService';
export { MerkleTreeUtils } from './utils/MerkleTreeUtils';

// Re-export commonly used types for convenience
export type {
    FlowKey,
    FlowControlledUserOp,
    MerkleTree,
    BundlerConfig,
    UserOpExecutionRequest,
    FlowSignatureRequest,
    FlowSignatureResponse
} from './types/flow-controlled';

// Version
export const VERSION = '1.0.0-flow-controlled';