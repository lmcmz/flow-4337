# Flow-Controlled ERC-4337 Architecture

## Overview

This document describes the complete architecture for the Flow-controlled ERC-4337 smart account system. This implementation replaces the previous ZKP-based approach with a simpler, more efficient system using Merkle proofs and direct signature verification.

## Core Components

### 1. Flow Chain Components

#### FlowKeyRegister.cdc
- **Purpose**: Global upgradable contract on Flow blockchain
- **Functionality**: 
  - Exposes active Flow public keys for any account
  - Returns keys in Flow account order (by keyIndex)
  - Supports both p256 and secp256k1 keys
  - Removes 04 prefix from public keys
  - Upgradable for future enhancements

**Key Functions:**
```cadence
getKeys(account: Address): [FlowKey]
getKeyCount(account: Address): UInt32
isKeyActive(account: Address, publicKey: String): Bool
```

### 2. EVM Chain Components

#### FlowRootRegistry.sol
- **Purpose**: Stores latest Merkle roots for Flow accounts
- **Access Control**: Single trusted bundler (POC implementation)
- **Features**:
  - Root freshness validation
  - Historical root tracking
  - Emergency admin controls
  - Merkle proof verification utilities

**Key Functions:**
```solidity
updateRoot(address flowAddress, bytes32 root, uint256 height, uint256 keyCount)
getRoot(address flowAddress) returns (bytes32)
verifyMerkleProof(bytes32 leaf, bytes32[] proof, bytes32 root) returns (bool)
```

#### FlowControlledSmartAccount.sol
- **Purpose**: ERC-4337 compatible smart account with Flow key verification
- **Validation**: Merkle proof + signature verification
- **Features**:
  - UUPS upgradeable
  - Batch operation support
  - Emergency recovery
  - Gas optimization

**Validation Logic:**
1. Verify Flow address matches linked account
2. Check operation hasn't been executed (replay protection)
3. Validate key weight meets minimum requirement
4. Verify signature algorithm support
5. Check Merkle root freshness
6. Verify Merkle proof for key inclusion
7. Validate signature using recovered address

### 3. Off-Chain Components

#### FlowControlledBundler
- **Purpose**: Monitors Flow chain and synchronizes Merkle roots
- **Responsibilities**:
  - Poll Flow key changes
  - Build deterministic Merkle trees
  - Update EVM registry when roots change
  - Generate Merkle proofs for user operations
  - Submit ERC-4337 operations to EntryPoint

**Process Flow:**
1. Monitor Flow accounts for key changes
2. Fetch current keys from FlowKeyRegister
3. Build Merkle tree with consistent ordering
4. Compare with stored root in EVM registry
5. Update registry if root changed
6. Process pending user operations

#### FlowControlledWallet
- **Purpose**: Wallet integration for Flow key management
- **Features**:
  - FCL integration for Flow authentication
  - Key discovery and management
  - Signature generation with Flow wallet
  - User operation creation
  - Batch operation support

## Data Structures

### FlowKey
```typescript
interface FlowKey {
    publicKey: string;          // 64 bytes hex, no 04 prefix
    weight: number;             // Key weight (1000 = 1.0)
    hashAlgorithm: number;      // 1=SHA2_256, 2=SHA3_256
    signatureAlgorithm: number; // 1=ECDSA_P256, 2=ECDSA_secp256k1
    isRevoked: boolean;         // Revocation status
    keyIndex: number;           // Original Flow key index
}
```

### FlowControlledUserOp
```typescript
interface FlowControlledUserOp {
    flowAddress: string;        // Flow account address
    opHash: string;             // keccak256(UserOperation)
    publicKey: string;          // Uncompressed key (64 bytes)
    weight: number;             // Key weight
    hashAlgorithm: number;      // Hash algorithm ID
    signatureAlgorithm: number; // Signature algorithm ID
    signature: string;          // Flow signature
    merkleProof: string[];      // Inclusion proof
}
```

### MerkleTree
```typescript
interface MerkleTree {
    root: string;               // Merkle root hash
    leaves: MerkleLeaf[];       // All leaves in order
    proofs: { [leafHash: string]: string[] }; // Proofs for each leaf
    totalKeys: number;          // Total key count
    blockHeight: number;        // Flow block height
    flowAddress: string;        // Flow account address
}
```

## Security Model

### Trust Assumptions
1. **Flow Blockchain**: Trusted source of key truth
2. **Bundler**: Trusted for root synchronization (POC)
3. **Smart Account**: Trustless verification via Merkle proofs
4. **Flow Wallet**: User controls private keys

### Security Features
1. **Replay Protection**: Operation hash tracking
2. **Key Weight Validation**: Minimum weight requirements
3. **Freshness Checks**: Root age validation
4. **Signature Verification**: Direct cryptographic validation
5. **Emergency Recovery**: Admin override capabilities

### Attack Vectors & Mitigations
1. **Stale Roots**: Timestamp-based freshness validation
2. **Invalid Proofs**: Cryptographic Merkle verification
3. **Replay Attacks**: Operation hash blacklisting
4. **Bundler Compromise**: Emergency admin controls + future decentralization
5. **Key Compromise**: Flow-level key revocation

## Gas Optimization

### Merkle Tree Efficiency
- Sorted leaf construction for deterministic roots
- Efficient proof verification (O(log n) complexity)
- Batch proof validation for multiple operations

### Smart Contract Optimizations
- Minimal storage reads via packed structs
- Gas-efficient signature verification
- Batch operation support
- Proxy pattern for upgradability

## Sequence Flows

### 1. Account Setup
```
1. User authenticates with Flow wallet
2. Bundler discovers Flow account and adds to monitoring
3. Bundler fetches initial keys from FlowKeyRegister
4. Bundler builds Merkle tree and updates EVM registry
5. Smart account proxy deployed and linked to Flow address
```

### 2. User Operation Execution
```
1. User signs operation hash with Flow wallet
2. Wallet creates FlowControlledUserOp (without proof)
3. Bundler fetches current Merkle tree and generates proof
4. Bundler adds proof to user operation
5. Bundler submits to EntryPoint for execution
6. Smart account validates proof and signature
7. Operation executed if validation passes
```

### 3. Key Update Handling
```
1. User adds/removes/updates keys on Flow
2. Bundler detects change during polling
3. Bundler fetches updated keys from FlowKeyRegister
4. Bundler builds new Merkle tree
5. Bundler updates root in EVM registry
6. Subsequent operations use new root
```

## Deployment Guide

### Prerequisites
- Flow testnet/mainnet access
- EVM blockchain access (Flow EVM recommended)
- Node.js 16+ environment
- Hardhat development framework

### Flow Deployment
```bash
# Deploy FlowKeyRegister.cdc to Flow
flow project deploy --network=testnet

# Configure contract address in bundler
export FLOW_KEY_REGISTER_ADDRESS="0x..."
```

### EVM Deployment
```bash
# Deploy EVM contracts
npx hardhat run scripts/deploy-flow-controlled.ts --network flow-testnet

# Note contract addresses for configuration
export FLOW_ROOT_REGISTRY_ADDRESS="0x..."
export SMART_ACCOUNT_IMPL_ADDRESS="0x..."
```

### Bundler Setup
```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with deployed contract addresses

# Start bundler service
npm run start:bundler
```

## Future Enhancements

### Decentralization Roadmap

#### Phase 1: Multi-Bundler Support
- Add bundler registration system
- Implement bundler rotation mechanism
- Add slashing conditions for malicious bundlers
- Multi-signature root updates

#### Phase 2: Validator Network
- Decentralized validator set for root verification
- Staking mechanism for validators
- Consensus mechanism for root updates
- Economic incentives and penalties

#### Phase 3: Full Decentralization
- Remove admin privileges
- Governance token for protocol updates
- Community-driven parameter changes
- Fully trustless operation

### Technical Improvements

#### Performance Optimizations
- Batch Merkle tree updates
- Compressed proof formats
- Lazy root synchronization
- Parallel operation processing

#### Feature Additions
- Multi-chain support via LayerZero integration
- Advanced signature schemes (BLS, Schnorr)
- Social recovery mechanisms
- Account abstraction enhancements

#### Security Enhancements
- Formal verification of critical contracts
- Time-locked upgrades
- Circuit breakers for emergency scenarios
- Advanced monitoring and alerting

## Testing Strategy

### Unit Tests
- Individual contract functionality
- Merkle tree operations
- Signature verification
- Error conditions

### Integration Tests
- End-to-end operation flows
- Cross-chain communication
- Bundler service integration
- Wallet integration

### Security Tests
- Attack vector validation
- Gas exhaustion protection
- Reentrancy protection
- Access control verification

### Performance Tests
- Large-scale Merkle tree operations
- Batch processing efficiency
- Gas consumption analysis
- Scalability limits

## Monitoring & Observability

### Key Metrics
- Root update frequency
- Operation success rate
- Average processing time
- Gas consumption trends
- Error rates by category

### Alerting
- Stale root detection
- Bundler health monitoring
- Unusual activity patterns
- Performance degradation

### Logging
- Structured operation logs
- Trace-level debugging
- Performance metrics
- Security event logging

## Conclusion

The Flow-controlled ERC-4337 architecture provides a robust, efficient, and secure foundation for cross-chain account control. The current POC implementation with a trusted bundler offers immediate functionality while maintaining a clear path toward full decentralization.

Key advantages over the previous ZKP approach:
- **Simplicity**: Direct signature verification vs complex ZKP circuits
- **Efficiency**: Lower gas costs and faster processing
- **Transparency**: All verification data is publicly auditable
- **Flexibility**: Easy to extend and modify without circuit changes

The architecture is designed for production use with appropriate security measures and monitoring, while providing a clear roadmap for decentralized operation.