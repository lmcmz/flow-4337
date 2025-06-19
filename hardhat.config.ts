import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-deploy";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true,
    },
    "flow-testnet": {
      url: "https://testnet.evm.nodes.onflow.org",
      accounts: process.env.FLOW_EVM_PRIVATE_KEY ? [process.env.FLOW_EVM_PRIVATE_KEY] : [],
      chainId: 545,
      gas: 5000000,
      gasPrice: 1000000000, // 1 gwei
    },
    "flow-mainnet": {
      url: "https://mainnet.evm.nodes.onflow.org",
      accounts: process.env.FLOW_EVM_PRIVATE_KEY ? [process.env.FLOW_EVM_PRIVATE_KEY] : [],
      chainId: 747,
      gas: 5000000,
      gasPrice: 1000000000, // 1 gwei
    },
  },
  namedAccounts: {
    deployer: {
      default: 0,
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: "USD",
  },
  etherscan: {
    apiKey: {
      "flow-testnet": "flow-testnet", // Placeholder
      "flow-mainnet": "flow-mainnet", // Placeholder
    },
    customChains: [
      {
        network: "flow-testnet",
        chainId: 545,
        urls: {
          apiURL: "https://evm-testnet.flowscan.org/api",
          browserURL: "https://evm-testnet.flowscan.org",
        },
      },
      {
        network: "flow-mainnet",
        chainId: 747,
        urls: {
          apiURL: "https://evm.flowscan.org/api",
          browserURL: "https://evm.flowscan.org",
        },
      },
    ],
  },
  typechain: {
    outDir: "typechain-types",
    target: "ethers-v5",
  },
};

export default config;