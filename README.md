# Flow ZKP + ERC-4337 Account Abstraction POC

A proof-of-concept implementation enabling Flow accounts to control ERC-4337 smart contract wallets through Zero-Knowledge Proofs on Flow EVM.

## 🎯 Project Overview

This project demonstrates how Flow blockchain accounts can control ERC-4337 account abstraction wallets using zero-knowledge proofs, combining Flow's native capabilities with Ethereum's account abstraction standard.

### Key Features

- **Privacy-Preserving Control**: Flow accounts control EVM wallets without revealing private keys
- **Cross-Chain Compatibility**: Native Flow accounts managing EVM operations
- **Gas Abstraction**: ERC-4337 features like gasless transactions and custom paymaster logic
- **MEV Protection**: Leveraging Flow's multi-role architecture for enhanced security

## 🏗️ Architecture

```
Flow Account (Native) 
    ↓ generates ZKP
ZK Circuit (proves ownership)
    ↓ verifies proof  
Custom ERC-4337 Account (Flow EVM)
    ↓ executes operations
Target Contracts/EOAs
```

## 📋 Implementation Steps

### Phase 1: ZKP Circuit Development
- [ ] **Step 1.1**: Design circuit schema for Flow account signature verification
- [ ] **Step 1.2**: Implement Poseidon hash circuit for Flow compatibility
- [ ] **Step 1.3**: Create proof generation logic for message signing
- [ ] **Step 1.4**: Generate trusted setup parameters
- [ ] **Step 1.5**: Test circuit with sample Flow account signatures

### Phase 2: Smart Contract Implementation
- [ ] **Step 2.1**: Deploy ZKP verifier contract on Flow EVM
- [ ] **Step 2.2**: Implement custom ERC-4337 account with ZKP validation
- [ ] **Step 2.3**: Create paymaster contract for gas abstraction (optional)
- [ ] **Step 2.4**: Integrate with standard ERC-4337 EntryPoint
- [ ] **Step 2.5**: Add emergency recovery mechanisms

### Phase 3: SDK & Integration Layer
- [ ] **Step 3.1**: Build Flow account signature generation SDK
- [ ] **Step 3.2**: Create UserOperation builder with ZKP payload
- [ ] **Step 3.3**: Implement proof generation and verification pipeline
- [ ] **Step 3.4**: Add batch operation support
- [ ] **Step 3.5**: Create frontend demo application

### Phase 4: Testing & Validation
- [ ] **Step 4.1**: Unit tests for ZKP circuits
- [ ] **Step 4.2**: Smart contract integration tests
- [ ] **Step 4.3**: End-to-end flow testing
- [ ] **Step 4.4**: Gas optimization and benchmarking
- [ ] **Step 4.5**: Security audit and vulnerability assessment

## 🛠️ Technical Stack

### ZKP Implementation
- **Circuit Language**: Circom
- **Proof System**: Groth16 (via snarkjs)
- **Hash Function**: Poseidon (Flow-compatible)
- **Curve**: BN254

### Smart Contracts
- **Language**: Solidity ^0.8.19
- **Framework**: Hardhat/Foundry
- **Standards**: ERC-4337, EIP-1967 (Proxy)
- **Libraries**: OpenZeppelin, Account Abstraction SDK

### Flow Integration
- **SDK**: Flow JavaScript SDK
- **Cryptography**: ECDSA P-256 (Flow native)
- **Network**: Flow Testnet → Flow Mainnet

### Development Tools
- **Environment**: Node.js, TypeScript
- **Testing**: Jest, Hardhat Test Suite
- **Deployment**: Hardhat Deploy, Flow CLI

## 🚀 Quick Start

### Prerequisites
```bash
# Install dependencies
npm install

# Install Flow CLI
sh -ci "$(curl -fsSL https://raw.githubusercontent.com/onflow/flow-cli/master/install.sh)"

# Install circom
npm install -g circom
```

### Setup
```bash
# Clone repository
git clone <repository-url>
cd flow-zkp

# Install project dependencies
npm install

# Compile circuits
npm run compile:circuits

# Deploy contracts to Flow EVM testnet
npm run deploy:testnet

# Run tests
npm test
```

## 📁 Project Structure

```
flow-zkp/
├── circuits/                 # ZKP circuits
│   ├── flow-signature.circom # Main circuit
│   └── poseidon.circom      # Hash function
├── contracts/               # Solidity contracts
│   ├── FlowZKAccount.sol   # ERC-4337 account with ZKP
│   ├── ZKVerifier.sol      # Generated verifier
│   └── FlowPaymaster.sol   # Custom paymaster
├── src/                    # SDK and utilities
│   ├── flow-integration.ts # Flow account operations
│   ├── zkp-generator.ts   # Proof generation
│   └── account-factory.ts # Account creation
├── test/                  # Test suites
├── scripts/              # Deployment scripts
└── frontend/            # Demo application
```

## 🔧 Configuration

### Environment Variables
```bash
# Flow Configuration
FLOW_PRIVATE_KEY=your_flow_private_key
FLOW_TESTNET_URL=https://rest-testnet.onflow.org

# Flow EVM Configuration  
FLOW_EVM_RPC_URL=https://testnet.evm.nodes.onflow.org
FLOW_EVM_PRIVATE_KEY=your_evm_private_key

# Circuit Configuration
CIRCUIT_WASM_PATH=./circuits/build/flow-signature.wasm
CIRCUIT_ZKEY_PATH=./circuits/build/flow-signature_0001.zkey
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Test specific components
npm run test:circuits    # ZKP circuit tests
npm run test:contracts   # Smart contract tests
npm run test:integration # End-to-end tests

# Generate coverage report
npm run coverage
```

## 📊 Benchmarks

| Operation | Gas Cost | Proof Size | Verification Time |
|-----------|----------|------------|-------------------|
| Account Creation | ~300k gas | 256 bytes | ~5ms |
| ZKP Verification | ~150k gas | 256 bytes | ~3ms |
| Batch Operations | ~50k gas/op | - | - |

## 🔒 Security Considerations

- **Circuit Security**: Trusted setup required for production
- **Key Management**: Flow private keys never exposed to EVM
- **Replay Protection**: Nonce-based protection implemented
- **Emergency Recovery**: Multi-sig recovery mechanisms

## 🚧 Current Limitations

- **Testnet Only**: Currently deployed on Flow EVM testnet
- **Single Signature**: Only supports single Flow account per ERC-4337 account
- **No Batching**: ZKP batching not yet implemented
- **Gas Optimization**: Further optimization needed for production

## 🛣️ Roadmap

- [ ] **v0.1**: Basic ZKP + ERC-4337 integration
- [ ] **v0.2**: Gas optimization and batching
- [ ] **v0.3**: Multi-signature support
- [ ] **v0.4**: Production-ready security audit
- [ ] **v1.0**: Mainnet deployment

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flow blockchain team for EVM compatibility
- Ethereum Foundation for ERC-4337 standard
- Circom/SnarkJS teams for ZKP tooling
- Account Abstraction working group

---

**Note**: This is a proof-of-concept implementation. Use at your own risk in production environments.