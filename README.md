# Flow-Controlled ERC-4337 Smart Accounts

A cross-chain control system where Flow accounts can control ERC-4337 smart accounts on EVM chains through Merkle proof verification. This implementation provides a secure, efficient alternative to ZKP-based approaches.

## 🎯 Overview

This system enables Flow blockchain users to control smart contract wallets on EVM chains (like Flow EVM) without exposing their private keys or requiring complex zero-knowledge proofs. Instead, it uses Merkle trees to efficiently prove key ownership and direct signature verification.

## 🏗️ Architecture

### Core Components

1. **Flow Chain**: `FlowKeyRegister.cdc` - Global registry of Flow account keys
2. **EVM Chain**: `FlowRootRegistry.sol` + `FlowControlledSmartAccount.sol` - Merkle root storage and verification
3. **Bundler Service**: Off-chain service for root synchronization and Merkle proof generation
4. **Wallet Integration**: Flow wallet integration for seamless user experience

### How It Works

```
Flow Account → Sign Operation → Bundler → Merkle Proof → EVM Execution
     ↓              ↓             ↓           ↓            ↓
  Private Key    Operation    Root Sync   Verification   Smart Account
```

## 🚀 Quick Start

### Prerequisites

- Node.js 16+
- Flow CLI
- Hardhat
- Access to Flow blockchain and EVM chain

### Installation

```bash
git clone <repository>
cd flow-zkp
git checkout flow-controlled-erc4337
npm install
```

### Deploy Contracts

1. **Deploy Flow Contract**:
```bash
flow project deploy --network=testnet
```

2. **Deploy EVM Contracts**:
```bash
npx hardhat run scripts/deploy-flow-controlled.ts --network flow-testnet
```

3. **Start Bundler Service**:
```bash
# Configure environment
cp .env.example .env
# Edit .env with deployed addresses

# Start bundler
npm run start:bundler
```

### Usage Example

```typescript
import { FlowControlledService } from './src';

// Initialize service
const service = new FlowControlledService({
    bundler: {
        flowEndpoint: 'https://rest-testnet.onflow.org',
        evmEndpoint: 'https://testnet.evm.nodes.onflow.org',
        flowKeyRegisterAddress: '0x...',
        flowRootRegistryAddress: '0x...',
        bundlerPrivateKey: process.env.BUNDLER_PRIVATE_KEY,
        pollingInterval: 30000,
        maxRootAge: 3600,
        batchSize: 10
    },
    wallet: {
        flowEndpoint: 'https://rest-testnet.onflow.org',
        flowKeyRegisterAddress: '0x...'
    }
});

// Initialize and authenticate
await service.initialize();
const flowAddress = await service.authenticateWallet();

// Execute smart contract call
const txHash = await service.executeCall(
    '0x...', // target contract
    '0x...', // call data
    '0'      // value
);

console.log(`Transaction executed: ${txHash}`);
```

## 📋 Features

### ✅ Implemented

- **Flow Key Management**: Automatic discovery and monitoring of Flow account keys
- **Merkle Tree Verification**: Efficient key inclusion proofs
- **Smart Account Control**: ERC-4337 compatible smart accounts
- **Bundler Service**: Automated root synchronization
- **Wallet Integration**: Flow wallet authentication and signing
- **Batch Operations**: Multiple operations in single transaction
- **Upgradeable Contracts**: UUPS proxy pattern for future improvements
- **Comprehensive Testing**: Unit, integration, and security tests

### 🔮 Future Enhancements

- **Decentralized Bundlers**: Multi-bundler support with staking
- **Cross-Chain Expansion**: LayerZero integration for other EVM chains
- **Advanced Features**: Social recovery, gas abstraction, account factories
- **Performance Optimizations**: Batch proofs, compressed formats

## 🔐 Security

### Current Model (POC)
- **Single Trusted Bundler**: Centralized root synchronization
- **Admin Controls**: Emergency recovery and upgrade capabilities
- **Cryptographic Verification**: Merkle proofs and signature validation

### Security Features
- **Replay Protection**: Operation hash tracking
- **Key Weight Validation**: Minimum weight requirements
- **Root Freshness**: Timestamp-based validation
- **Emergency Recovery**: Admin override capabilities

### Future Decentralization
See [Architecture Documentation](./docs/FLOW_CONTROLLED_ARCHITECTURE.md) for detailed decentralization roadmap.

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# Gas usage analysis
npm run test:gas

# Security tests
npm run test:security
```

## 📊 Performance

### Gas Costs (Estimated)
- **Root Update**: ~80,000 gas
- **User Operation Validation**: ~50,000 gas
- **Batch Operations**: ~30,000 gas per additional operation
- **Smart Account Deployment**: ~200,000 gas

### Throughput
- **Root Updates**: ~1 per minute per Flow account
- **User Operations**: Limited by EVM block capacity
- **Bundler Processing**: ~100 operations per second

## 🔧 Configuration

### Bundler Configuration

```typescript
interface BundlerConfig {
    flowEndpoint: string;           // Flow RPC endpoint
    evmEndpoint: string;            // EVM RPC endpoint
    flowKeyRegisterAddress: string; // Flow contract address
    flowRootRegistryAddress: string;// EVM contract address
    bundlerPrivateKey: string;      // Bundler private key
    pollingInterval: number;        // Polling interval (ms)
    maxRootAge: number;             // Max root age (sec)
    batchSize: number;              // Batch processing size
}
```

### Wallet Configuration

```typescript
interface FlowWalletConfig {
    flowEndpoint: string;           // Flow RPC endpoint
    walletDiscovery?: string;       // Wallet discovery URL
    flowKeyRegisterAddress: string; // Flow contract address
}
```

## 📖 Documentation

- [Architecture Guide](./docs/FLOW_CONTROLLED_ARCHITECTURE.md) - Detailed system architecture
- [API Reference](./docs/API_REFERENCE.md) - Complete API documentation
- [Security Analysis](./docs/SECURITY_ANALYSIS.md) - Security model and analysis
- [Deployment Guide](./docs/DEPLOYMENT_GUIDE.md) - Production deployment instructions

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flow blockchain team for the robust account abstraction system
- ERC-4337 standard authors for the account abstraction framework
- OpenZeppelin for secure smart contract libraries
- Ethereum community for the foundational technologies

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/flow-zkp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/flow-zkp/discussions)
- **Documentation**: [Docs Site](https://docs.your-org.com/flow-controlled)

---

**Note**: This is a POC implementation with a trusted bundler. See the architecture documentation for the decentralization roadmap and production considerations.