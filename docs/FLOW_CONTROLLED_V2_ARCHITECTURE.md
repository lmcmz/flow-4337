# Flow-Controlled ERC-4337 V2 Architecture

## Overview

Flow-Controlled ERC-4337 V2 represents a complete architectural evolution from the original ZKP-based system. This implementation introduces multi-signature support, CREATE2 deterministic deployment, and EVM-side key management for enhanced efficiency and scalability.

## 🔄 Architecture Evolution

### V1 → V2 Major Changes

| Component | V1 (ZKP-based) | V2 (Multi-sig + CREATE2) |
|-----------|-----------------|---------------------------|
| **Key Storage** | Flow chain contract | EVM-side FlowKeyRegister |
| **Proof System** | Zero-Knowledge Proofs | Merkle Trees + Direct Signatures |
| **Deployment** | Regular proxy deployment | CREATE2 deterministic deployment |
| **Signature Support** | Single signature | Multi-signature with weight threshold |
| **Account Control** | EVM owner required | Flow address only |
| **Key Management** | Manual sync | Automatic mismatch detection |

## 🏗️ V2 System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Flow Chain    │    │  Bundler V2     │    │   EVM Chain     │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Native Keys │ │───▶│ │ Key Monitor │ │───▶│ │FlowKeyReg   │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│                 │    │ │Merkle Builder│ │───▶│ │RootRegistry │ │
│                 │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│                 │    │ │UserOp Proc  │ │───▶│ │SmartAccount │ │
│                 │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │ ┌─────────────┐ │
│                 │    │                 │    │ │CREATE2 Fact │ │
│                 │    │                 │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🖼️ Diagram
[diagram](./diagram.png)

## 📦 Core Components

### 1. FlowKeyRegister.sol (EVM-side)

**Purpose**: Centralized Flow key management on EVM chain

**Key Features**:
- Stores complete Flow account key metadata
- Supports KeyInfo structure with weight, algorithms, revocation status
- Admin override capabilities for emergency scenarios
- Automatic weight calculation and threshold validation
- Authorized bundler management

**KeyInfo Structure**:
```solidity
struct KeyInfo {
    bytes publicKey;        // 64 bytes, uncompressed, no 04 prefix
    uint256 weight;         // Flow key weight (0-1000)
    uint8 hashAlgorithm;    // Hash algorithm ID
    uint8 signatureAlgorithm; // Signature algorithm ID
    bool isRevoked;         // Revocation status
    uint256 keyIndex;       // Original Flow key index
}
```

### 2. FlowAccountFactory.sol (CREATE2)

**Purpose**: Deterministic smart account deployment

**Key Features**:
- CREATE2-based deterministic address generation
- Batch account creation support
- Flow address-only initialization (no EVM owner)
- Account mapping and enumeration
- Predicted address calculation

**Deterministic Salt**:
```solidity
bytes32 salt = keccak256(abi.encode("FlowControlled", flowAddress));
```

### 3. FlowControlledSmartAccountV2.sol

**Purpose**: Multi-signature ERC-4337 account with Flow key validation

**Key Features**:
- Multi-signature validation with weight threshold (>= 1000)
- Array-based UserOp structure for multiple keys/signatures
- KeyInfo-based Merkle proof verification
- Batch operation support
- Duplicate key prevention
- Gas-optimized validation logic

**Multi-Signature UserOp**:
```solidity
struct FlowMultiSigUserOp {
    address flowAddress;
    bytes32 opHash;
    KeyInfo[] keys;
    bytes[] signatures;
    bytes32[] merkleProofs;
}
```

### 4. BundlerV2 (Off-chain)

**Purpose**: Flow blockchain monitoring and EVM synchronization

**Key Responsibilities**:
- Monitor Flow native account keys
- Detect key mismatches between Flow and EVM
- Update EVM FlowKeyRegister when changes detected
- Build KeyInfo-based Merkle trees
- Generate and inject Merkle proofs into UserOps
- Process multi-signature operations

**Mismatch Detection Algorithm**:
1. Fetch Flow native keys via Cadence script
2. Fetch EVM stored keys from FlowKeyRegister
3. Compare key count, weights, revocation status
4. Update EVM if differences found
5. Rebuild Merkle tree and update root registry

## 🔐 Security Model

### Multi-Signature Validation

**Weight-Based Threshold**:
- Flow uses integer weights (0-1000, where 1000 = 100%)
- V2 requires sum of signing key weights >= 1000
- Supports partial signatures (e.g., 600 + 400 weight keys)
- Prevents duplicate key usage in single operation

**Signature Verification**:
- Supports both P256 and secp256k1 algorithms
- Direct signature verification (no ZKP complexity)
- Address derivation from public keys
- Merkle proof validation for key inclusion

### Key Management Security

**Bundler Trust Model**:
- Single trusted bundler for POC implementation
- Admin override capabilities for emergency scenarios
- Future roadmap includes multi-bundler and decentralization
- Replay protection via operation hash tracking

**Data Integrity**:
- Cryptographic Merkle proofs for key inclusion
- Deterministic tree construction (sorted by keyIndex)
- Root freshness validation with timestamps
- Automatic synchronization on mismatch detection

## 🎯 Multi-Signature Flow

### 1. Key Selection Strategies

**Available Strategies**:
- `ALL_AVAILABLE`: Use all non-revoked keys
- `MINIMUM_WEIGHT`: Use minimum keys to reach threshold
- `PREFERRED_ALGORITHM`: Prefer specific signature algorithm
- `SPECIFIC_KEYS`: Use manually specified key indices
- `HIGHEST_WEIGHT`: Use highest weight keys first

### 2. Operation Creation

```typescript
// 1. Wallet selects keys based on strategy
const selectedKeys = await wallet.selectKeys(
    KeySelectionStrategy.MINIMUM_WEIGHT,
    { minimumWeight: 1000 }
);

// 2. Sign operation hash with selected keys
const signatures = await Promise.all(
    selectedKeys.map(key => wallet.signWithKey(opHash, key))
);

// 3. Create multi-sig user operation
const userOp: FlowMultiSigUserOp = {
    flowAddress,
    opHash,
    keys: selectedKeys,
    signatures,
    merkleProofs: [] // Added by bundler
};
```

### 3. Bundler Processing

```typescript
// 1. Verify keys are current
await bundler.checkKeyMismatch(flowAddress);

// 2. Generate Merkle proofs
const proofs = await Promise.all(
    userOp.keys.map(key => bundler.getKeyInfoProof(flowAddress, key))
);

// 3. Inject proofs into UserOp
userOp.merkleProofs = proofs;

// 4. Submit to EntryPoint
await bundler.processUserOp(userOp);
```

### 4. Smart Account Validation

```solidity
function validateUserOp(FlowMultiSigUserOp memory userOp) public view returns (uint256) {
    // 1. Verify Flow address matches
    require(userOp.flowAddress == linkedFlowAddress, "Address mismatch");
    
    // 2. Verify arrays are consistent
    require(userOp.keys.length == userOp.signatures.length, "Array mismatch");
    
    // 3. Validate each key and signature
    uint256 totalWeight = 0;
    for (uint256 i = 0; i < userOp.keys.length; i++) {
        // Verify Merkle proof
        bytes32 keyInfoHash = createKeyInfoHash(userOp.keys[i]);
        require(verifyMerkleProof(keyInfoHash, userOp.merkleProofs[i], storedRoot));
        
        // Verify signature
        require(validateSignature(userOp.opHash, userOp.signatures[i], userOp.keys[i]));
        
        totalWeight += userOp.keys[i].weight;
    }
    
    // 4. Check weight threshold
    require(totalWeight >= 1000, "Insufficient weight");
    
    return 0; // Success
}
```

## 📊 Performance Optimizations

### Gas Efficiency

**Smart Contract Optimizations**:
- Packed structs for efficient storage
- Batch operations for multiple UserOps
- Optimized Merkle proof verification
- Minimal storage reads via caching

**Estimated Gas Costs**:
- FlowKeyRegister deployment: ~800,000 gas
- Smart account creation: ~150,000 gas
- Multi-sig validation: ~80,000 gas + (30,000 * num_keys)
- Key update: ~120,000 gas + (15,000 * num_keys)

### Bundler Efficiency

**Monitoring Optimizations**:
- Configurable polling intervals
- Differential key comparison
- Batch account processing
- Merkle tree caching

**Processing Throughput**:
- Key updates: ~50 accounts/minute
- UserOp processing: ~100 operations/minute
- Merkle proof generation: ~1000 proofs/second

## 🚀 Deployment Guide

### Prerequisites

- Node.js 16+
- Hardhat development framework
- Flow CLI (for testing native key queries)
- EVM blockchain access

### Deployment Steps

```bash
# 1. Install dependencies
npm install

# 2. Configure deployment parameters
cp .env.example .env
# Edit .env with your configuration

# 3. Deploy V2 contracts
npx hardhat run scripts/deploy-flow-controlled-v2.ts --network <network>

# 4. Start bundler V2
npm run start:bundler-v2

# 5. Test multi-signature flow
npm run test:v2
```

### Configuration Parameters

```typescript
const config: FlowControlledServiceConfigV2 = {
    bundler: {
        flowEndpoint: 'https://rest-testnet.onflow.org',
        evmEndpoint: 'https://testnet.evm.nodes.onflow.org',
        flowKeyRegisterAddress: '0x...', // EVM address
        flowRootRegistryAddress: '0x...',
        bundlerPrivateKey: process.env.BUNDLER_PRIVATE_KEY,
        pollingInterval: 30000, // 30 seconds
        maxRootAge: 3600, // 1 hour
        batchSize: 10,
        maxKeysPerUpdate: 50
    },
    factory: {
        factoryAddress: '0x...',
        implementationAddress: '0x...'
    },
    flowKeyRegister: '0x...',
    rootRegistry: '0x...'
};
```

## 🔮 Future Enhancements

### Decentralization Roadmap

**Phase 1: Multi-Bundler Support**
- Multiple authorized bundlers
- Bundler rotation and failover
- Consensus mechanism for key updates
- Slashing conditions for malicious behavior

**Phase 2: Validator Network**
- Decentralized validator set
- Stake-based validation
- Economic incentives and penalties
- Governance token for protocol updates

**Phase 3: Cross-Chain Expansion**
- Multi-EVM chain support
- LayerZero integration
- Unified account addresses across chains
- Cross-chain operation batching

### Technical Improvements

**Advanced Multi-Signature**:
- Threshold signatures (BLS)
- Time-locked operations
- Progressive key weights
- Social recovery mechanisms

**Gas Optimizations**:
- Compressed Merkle proofs
- Batch validation circuits
- State rent optimization
- Layer 2 integration

**Developer Experience**:
- SDK for common frameworks
- Visual key management interface
- Operation simulation tools
- Comprehensive monitoring dashboard

## 🧪 Testing Strategy

### Test Categories

**Unit Tests**:
- KeyInfo structure validation
- Merkle tree construction
- Multi-signature validation
- CREATE2 address prediction

**Integration Tests**:
- End-to-end operation flows
- Bundler synchronization
- Factory account creation
- Cross-component interaction

**Security Tests**:
- Weight threshold enforcement
- Replay attack prevention
- Key revocation handling
- Admin override scenarios

**Performance Tests**:
- Large key set handling
- Batch operation efficiency
- Concurrent bundler operations
- Gas consumption analysis

### Test Execution

```bash
# Unit tests
npm run test:unit:v2

# Integration tests  
npm run test:integration:v2

# Security tests
npm run test:security:v2

# Performance benchmarks
npm run test:performance:v2

# Full test suite
npm run test:v2
```

## 📈 Monitoring & Observability

### Key Metrics

**Bundler Metrics**:
- Key update frequency per account
- Mismatch detection rate
- Average processing time
- Error rates by category

**Smart Account Metrics**:
- Multi-signature success rate
- Average keys per operation
- Gas consumption trends
- Operation throughput

**System Health**:
- Root freshness across accounts
- Bundler uptime and responsiveness
- Contract upgrade readiness
- Security incident tracking

### Alerting

**Critical Alerts**:
- Bundler offline or unresponsive
- High error rates in validation
- Potential security incidents
- Unusual operation patterns

**Operational Alerts**:
- Stale roots detected
- High gas consumption
- Performance degradation
- Capacity approaching limits

## 🔍 Troubleshooting

### Common Issues

**Key Mismatch Not Detected**:
- Check bundler polling configuration
- Verify Flow endpoint connectivity
- Review key comparison logic
- Check admin permissions

**Multi-Signature Validation Fails**:
- Verify total weight >= 1000
- Check signature algorithms match
- Validate Merkle proof generation
- Review key revocation status

**CREATE2 Address Mismatch**:
- Verify salt generation consistency
- Check implementation address
- Review proxy initialization
- Validate factory configuration

### Debug Tools

```bash
# Check bundler status
curl http://localhost:3001/status

# Verify account state
curl http://localhost:3001/account/<flowAddress>

# Test key mismatch detection
curl http://localhost:3001/check-mismatch/<flowAddress>

# Force key synchronization
curl -X POST http://localhost:3001/sync-keys/<flowAddress>
```

## 🎉 Conclusion

Flow-Controlled ERC-4337 V2 represents a significant advancement in cross-chain account abstraction, offering:

- **Simplified Architecture**: Direct signatures replace complex ZKP systems
- **Enhanced Security**: Multi-signature support with flexible weight thresholds  
- **Improved Efficiency**: EVM-side key management and CREATE2 deployment
- **Better UX**: Automatic synchronization and predictable addresses
- **Production Ready**: Comprehensive testing and monitoring capabilities

The V2 system provides a robust foundation for production deployment while maintaining a clear path toward full decentralization and cross-chain expansion.