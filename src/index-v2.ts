/**
 * @file index-v2.ts
 * @description Main entry point for Flow-controlled ERC-4337 V2 implementation
 * Exports all V2 components with multi-signature and CREATE2 support
 */

// Core V2 components
export { FlowControlledBundlerV2 } from './bundler/FlowControlledBundlerV2';
export { FlowControlledWalletV2 } from './wallet/FlowControlledWalletV2';
export { FlowControlledServiceV2 } from './services/FlowControlledServiceV2';

// Utilities
export { MerkleTreeUtils } from './utils/MerkleTreeUtilsV2';

// Type definitions
export * from './types/flow-controlled-v2';

// Re-export commonly used types for convenience
export type {
    KeyInfo,
    FlowMultiSigUserOp,
    KeyInfoMerkleTree,
    BundlerConfigV2,
    UserOpExecutionRequestV2,
    MultiSigRequest,
    MultiSigResponse,
    AccountCreationRequest,
    AccountCreationResponse,
    FlowControlledServiceConfigV2
} from './types/flow-controlled-v2';

// Re-export enums
export {
    SignatureAlgorithm,
    HashAlgorithm,
    KeySelectionStrategy,
    FlowControlledErrorV2
} from './types/flow-controlled-v2';

// Version and metadata
export const VERSION_V2 = '2.0.0-multisig-create2';
export const FEATURES = [
    'CREATE2 deterministic deployment',
    'Multi-signature validation',
    'EVM-side Flow key management', 
    'KeyInfo-based Merkle trees',
    'Weight-based threshold (>= 1000)',
    'Batch operations support',
    'Admin override capabilities',
    'Automatic key mismatch detection',
    'Flow blockchain monitoring',
    'Gas optimized contracts'
];

/**
 * Quick start helper function for V2
 */
export function createFlowControlledServiceV2(config: {
    flowEndpoint: string;
    evmEndpoint: string;
    bundlerPrivateKey: string;
    flowKeyRegisterAddress: string;
    flowRootRegistryAddress: string;
    factoryAddress: string;
    implementationAddress: string;
    pollingInterval?: number;
    maxRootAge?: number;
}): FlowControlledServiceV2 {
    const serviceConfig: FlowControlledServiceConfigV2 = {
        bundler: {
            flowEndpoint: config.flowEndpoint,
            evmEndpoint: config.evmEndpoint,
            flowKeyRegisterAddress: config.flowKeyRegisterAddress,
            flowRootRegistryAddress: config.flowRootRegistryAddress,
            bundlerPrivateKey: config.bundlerPrivateKey,
            pollingInterval: config.pollingInterval || 30000,
            maxRootAge: config.maxRootAge || 3600,
            batchSize: 10,
            maxKeysPerUpdate: 50
        },
        factory: {
            factoryAddress: config.factoryAddress,
            implementationAddress: config.implementationAddress
        },
        flowKeyRegister: config.flowKeyRegisterAddress,
        rootRegistry: config.flowRootRegistryAddress
    };

    return new FlowControlledServiceV2(serviceConfig);
}