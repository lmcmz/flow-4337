/**
 * @file deploy-flow-controlled-v2.ts
 * @description Deployment script for Flow-controlled ERC-4337 V2 system with CREATE2 factory
 */

import { ethers } from 'hardhat';
import { 
    FlowKeyRegister, 
    FlowRootRegistry, 
    FlowControlledSmartAccountV2,
    FlowAccountFactory 
} from '../typechain';

async function main() {
    console.log('🚀 Deploying Flow-controlled ERC-4337 V2 system...');

    const [deployer, bundler, admin] = await ethers.getSigners();
    
    console.log('📋 Deployment Configuration:');
    console.log(`  Deployer: ${deployer.address}`);
    console.log(`  Bundler: ${bundler.address}`);
    console.log(`  Admin: ${admin.address}`);
    console.log(`  Network: ${(await ethers.provider.getNetwork()).name}`);
    console.log(`  Chain ID: ${(await ethers.provider.getNetwork()).chainId}`);

    // 1. Deploy FlowKeyRegister (EVM-side key management)
    console.log('\n1️⃣ Deploying FlowKeyRegister...');
    
    const FlowKeyRegisterFactory = await ethers.getContractFactory('FlowKeyRegister');
    const flowKeyRegister = await FlowKeyRegisterFactory.deploy(bundler.address);
    await flowKeyRegister.deployed();
    
    console.log(`✅ FlowKeyRegister deployed at: ${flowKeyRegister.address}`);
    console.log(`   Primary bundler: ${await flowKeyRegister.primaryBundler()}`);
    console.log(`   Max keys per account: ${await flowKeyRegister.maxKeysPerAccount()}`);

    // 2. Deploy FlowRootRegistry
    console.log('\n2️⃣ Deploying FlowRootRegistry...');
    
    const FlowRootRegistryFactory = await ethers.getContractFactory('FlowRootRegistry');
    const flowRootRegistry = await FlowRootRegistryFactory.deploy(bundler.address);
    await flowRootRegistry.deployed();
    
    console.log(`✅ FlowRootRegistry deployed at: ${flowRootRegistry.address}`);
    console.log(`   Trusted bundler: ${await flowRootRegistry.trustedBundler()}`);

    // 3. Deploy SmartAccount implementation
    console.log('\n3️⃣ Deploying FlowControlledSmartAccountV2 implementation...');
    
    const SmartAccountFactory = await ethers.getContractFactory('FlowControlledSmartAccountV2');
    const smartAccountImpl = await SmartAccountFactory.deploy();
    await smartAccountImpl.deployed();
    
    console.log(`✅ SmartAccountV2 implementation deployed at: ${smartAccountImpl.address}`);

    // 4. Deploy CREATE2 Account Factory
    console.log('\n4️⃣ Deploying FlowAccountFactory...');
    
    const FactoryFactory = await ethers.getContractFactory('FlowAccountFactory');
    const accountFactory = await FactoryFactory.deploy(
        smartAccountImpl.address,
        flowRootRegistry.address
    );
    await accountFactory.deployed();
    
    console.log(`✅ FlowAccountFactory deployed at: ${accountFactory.address}`);
    
    const factoryInfo = await accountFactory.getFactoryInfo();
    console.log(`   Implementation: ${factoryInfo.impl}`);
    console.log(`   Registry: ${factoryInfo.registry}`);

    // 5. Create sample smart account using CREATE2
    console.log('\n5️⃣ Creating sample smart account with CREATE2...');
    
    const sampleFlowAddress = ethers.utils.getAddress(
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes('sample-flow-account-v2')).slice(0, 42)
    );
    
    // Predict address first
    const predictedAddress = await accountFactory.getAddress(sampleFlowAddress);
    console.log(`   Predicted address: ${predictedAddress}`);
    
    // Create account
    const createTx = await accountFactory.createAccount(sampleFlowAddress);
    const createReceipt = await createTx.wait();
    const createEvent = createReceipt.events?.find(e => e.event === 'AccountCreated');
    const actualAddress = createEvent?.args?.account;
    
    console.log(`✅ Sample smart account created at: ${actualAddress}`);
    console.log(`   Address matches prediction: ${actualAddress === predictedAddress}`);
    console.log(`   Linked Flow address: ${sampleFlowAddress}`);

    // 6. Configure smart account
    console.log('\n6️⃣ Configuring smart account...');
    
    const smartAccount = SmartAccountFactory.attach(actualAddress);
    
    // Set FlowKeyRegister address
    await smartAccount.setFlowKeyRegister(flowKeyRegister.address);
    
    const accountInfo = await smartAccount.getAccountInfo();
    console.log(`   Configuration verified:`);
    console.log(`     Flow address: ${accountInfo.flowAddress}`);
    console.log(`     Registry: ${accountInfo.registryAddress}`);
    console.log(`     Key register: ${accountInfo.keyRegisterAddress}`);

    // 7. Add sample keys to demonstrate the system
    console.log('\n7️⃣ Adding sample keys to demonstrate multi-signature...');
    
    const sampleKeys = [
        {
            publicKey: '0x' + '1234567890abcdef'.repeat(8), // 64 bytes
            weight: 600,
            hashAlgorithm: 1, // SHA2_256
            signatureAlgorithm: 2, // ECDSA_secp256k1
            isRevoked: false,
            keyIndex: 0
        },
        {
            publicKey: '0x' + 'abcdef1234567890'.repeat(8), // 64 bytes
            weight: 400,
            hashAlgorithm: 1, // SHA2_256
            signatureAlgorithm: 1, // ECDSA_P256
            isRevoked: false,
            keyIndex: 1
        }
    ];

    await flowKeyRegister.connect(bundler).updateKeys(
        sampleFlowAddress,
        sampleKeys,
        12345 // Sample block height
    );

    const accountState = await flowKeyRegister.getAccountState(sampleFlowAddress);
    console.log(`   Keys added: ${accountState.keyCount}`);
    console.log(`   Total weight: ${accountState.totalWeight}`);
    console.log(`   Sufficient weight: ${accountState.totalWeight >= 1000}`);

    // 8. Update Merkle root
    console.log('\n8️⃣ Updating Merkle root...');
    
    // Get KeyInfo hashes for Merkle tree
    const keyInfoHashes = await flowKeyRegister.getKeyInfoHashes(sampleFlowAddress);
    console.log(`   KeyInfo hashes: ${keyInfoHashes.length}`);
    
    // For demo, create a simple root (in production, bundler would build full tree)
    const simpleRoot = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(['bytes32[]'], [keyInfoHashes])
    );
    
    await flowRootRegistry.connect(bundler).updateRoot(
        sampleFlowAddress,
        simpleRoot,
        12345,
        sampleKeys.length
    );

    const storedRoot = await flowRootRegistry.getRoot(sampleFlowAddress);
    console.log(`✅ Merkle root updated: ${storedRoot}`);

    // 9. Test account factory batch creation
    console.log('\n9️⃣ Testing batch account creation...');
    
    const batchFlowAddresses = [
        ethers.utils.getAddress(ethers.utils.keccak256(ethers.utils.toUtf8Bytes('batch-account-1')).slice(0, 42)),
        ethers.utils.getAddress(ethers.utils.keccak256(ethers.utils.toUtf8Bytes('batch-account-2')).slice(0, 42))
    ];

    const batchTx = await accountFactory.batchCreateAccounts(batchFlowAddresses);
    const batchReceipt = await batchTx.wait();
    const batchEvents = batchReceipt.events?.filter(e => e.event === 'AccountCreated');

    console.log(`✅ Batch created ${batchEvents?.length} accounts`);
    console.log(`   Total accounts: ${await accountFactory.getAccountCount()}`);

    // 10. Output deployment summary
    console.log('\n📄 Deployment Summary:');
    console.log('='.repeat(60));
    console.log(`FlowKeyRegister:        ${flowKeyRegister.address}`);
    console.log(`FlowRootRegistry:       ${flowRootRegistry.address}`);
    console.log(`SmartAccountV2 Impl:    ${smartAccountImpl.address}`);
    console.log(`FlowAccountFactory:     ${accountFactory.address}`);
    console.log(`Sample Smart Account:   ${actualAddress}`);
    console.log(`Sample Flow Address:    ${sampleFlowAddress}`);
    console.log(`Primary Bundler:        ${bundler.address}`);
    console.log(`Admin:                  ${admin.address}`);
    
    // 11. Calculate gas usage
    console.log('\n⛽ Gas Usage Summary:');
    console.log('='.repeat(60));
    const gasUsed = {
        flowKeyRegister: (await flowKeyRegister.deployTransaction.wait()).gasUsed,
        flowRootRegistry: (await flowRootRegistry.deployTransaction.wait()).gasUsed,
        smartAccountImpl: (await smartAccountImpl.deployTransaction.wait()).gasUsed,
        accountFactory: (await accountFactory.deployTransaction.wait()).gasUsed,
        accountCreation: createReceipt.gasUsed,
        batchCreation: batchReceipt.gasUsed
    };

    Object.entries(gasUsed).forEach(([contract, gas]) => {
        console.log(`${contract.padEnd(20)}: ${gas.toString().padStart(10)} gas`);
    });

    const totalGas = Object.values(gasUsed).reduce((sum, gas) => sum.add(gas), ethers.BigNumber.from(0));
    console.log(`${'Total'.padEnd(20)}: ${totalGas.toString().padStart(10)} gas`);

    // 12. Save deployment info
    const deploymentInfo = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId,
        timestamp: new Date().toISOString(),
        version: "2.0.0-multisig-create2",
        contracts: {
            flowKeyRegister: flowKeyRegister.address,
            flowRootRegistry: flowRootRegistry.address,
            smartAccountImpl: smartAccountImpl.address,
            accountFactory: accountFactory.address,
            sampleSmartAccount: actualAddress
        },
        configuration: {
            primaryBundler: bundler.address,
            admin: admin.address,
            sampleFlowAddress: sampleFlowAddress,
            maxKeysPerAccount: await flowKeyRegister.maxKeysPerAccount(),
            weightThreshold: 1000
        },
        gasUsage: Object.fromEntries(
            Object.entries(gasUsed).map(([key, value]) => [key, value.toString()])
        ),
        features: [
            "CREATE2 deterministic deployment",
            "Multi-signature validation (weight >= 1000)",
            "EVM-side Flow key management",
            "KeyInfo-based Merkle trees",
            "Batch account creation",
            "Admin override capabilities",
            "Mismatch detection and auto-sync"
        ]
    };

    const fs = require('fs');
    const path = require('path');
    
    const deploymentDir = path.join(__dirname, '../deployments');
    if (!fs.existsSync(deploymentDir)) {
        fs.mkdirSync(deploymentDir, { recursive: true });
    }
    
    const filename = `flow-controlled-v2-${deploymentInfo.network}-${Date.now()}.json`;
    fs.writeFileSync(
        path.join(deploymentDir, filename),
        JSON.stringify(deploymentInfo, null, 2)
    );
    
    console.log(`\n💾 Deployment info saved to: deployments/${filename}`);
    
    // 13. Next steps and configuration
    console.log('\n🎯 Next Steps:');
    console.log('1. Configure bundler with deployed contract addresses');
    console.log('2. Set up Flow blockchain monitoring for key changes');
    console.log('3. Deploy to additional EVM chains if needed');
    console.log('4. Set up proper key management and admin procedures');
    console.log('5. Test end-to-end multi-signature flows');
    
    console.log('\n🔧 Bundler Configuration:');
    console.log(`FLOW_KEY_REGISTER_ADDRESS="${flowKeyRegister.address}"`);
    console.log(`FLOW_ROOT_REGISTRY_ADDRESS="${flowRootRegistry.address}"`);
    console.log(`ACCOUNT_FACTORY_ADDRESS="${accountFactory.address}"`);
    console.log(`BUNDLER_PRIVATE_KEY="<your-bundler-private-key>"`);
    console.log(`ADMIN_ADDRESS="${admin.address}"`);
    
    console.log('\n✨ Deployment completed successfully!');
    console.log('🚀 Flow-controlled ERC-4337 V2 system is ready for use!');
}

// Execute deployment
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('❌ Deployment failed:', error);
        process.exit(1);
    });