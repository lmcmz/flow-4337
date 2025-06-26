/**
 * @file deploy-flow-controlled.ts
 * @description Deployment script for Flow-controlled ERC-4337 system
 */

import { ethers } from 'hardhat';
import { FlowRootRegistry, FlowControlledSmartAccount } from '../typechain';

async function main() {
    console.log('🚀 Deploying Flow-controlled ERC-4337 system...');

    const [deployer, bundler] = await ethers.getSigners();
    
    console.log('📋 Deployment Configuration:');
    console.log(`  Deployer: ${deployer.address}`);
    console.log(`  Bundler: ${bundler.address}`);
    console.log(`  Network: ${(await ethers.provider.getNetwork()).name}`);
    console.log(`  Chain ID: ${(await ethers.provider.getNetwork()).chainId}`);

    // 1. Deploy FlowRootRegistry
    console.log('\n1️⃣ Deploying FlowRootRegistry...');
    
    const FlowRootRegistryFactory = await ethers.getContractFactory('FlowRootRegistry');
    const flowRootRegistry = await FlowRootRegistryFactory.deploy(bundler.address);
    await flowRootRegistry.deployed();
    
    console.log(`✅ FlowRootRegistry deployed at: ${flowRootRegistry.address}`);
    console.log(`   Trusted bundler: ${await flowRootRegistry.trustedBundler()}`);

    // 2. Deploy SmartAccount implementation
    console.log('\n2️⃣ Deploying FlowControlledSmartAccount implementation...');
    
    const SmartAccountFactory = await ethers.getContractFactory('FlowControlledSmartAccount');
    const smartAccountImpl = await SmartAccountFactory.deploy();
    await smartAccountImpl.deployed();
    
    console.log(`✅ SmartAccount implementation deployed at: ${smartAccountImpl.address}`);

    // 3. Create sample smart account instance
    console.log('\n3️⃣ Creating sample smart account instance...');
    
    const sampleFlowAddress = ethers.utils.getAddress(
        ethers.utils.keccak256(ethers.utils.toUtf8Bytes('sample-flow-account')).slice(0, 42)
    );
    
    const ProxyFactory = await ethers.getContractFactory('ERC1967Proxy');
    const initData = smartAccountImpl.interface.encodeFunctionData('initialize', [
        flowRootRegistry.address,
        sampleFlowAddress,
        deployer.address
    ]);
    
    const proxy = await ProxyFactory.deploy(smartAccountImpl.address, initData);
    await proxy.deployed();
    
    const smartAccount = SmartAccountFactory.attach(proxy.address);
    
    console.log(`✅ Sample smart account created at: ${smartAccount.address}`);
    console.log(`   Linked Flow address: ${sampleFlowAddress}`);

    // 4. Verify deployments
    console.log('\n4️⃣ Verifying deployments...');
    
    const accountInfo = await smartAccount.getAccountInfo();
    console.log(`   Account info verified:`);
    console.log(`     Flow address: ${accountInfo.flowAddress}`);
    console.log(`     Registry address: ${accountInfo.registryAddress}`);
    
    // 5. Output deployment summary
    console.log('\n📄 Deployment Summary:');
    console.log('='.repeat(50));
    console.log(`FlowRootRegistry: ${flowRootRegistry.address}`);
    console.log(`SmartAccount Implementation: ${smartAccountImpl.address}`);
    console.log(`Sample Smart Account: ${smartAccount.address}`);
    console.log(`Trusted Bundler: ${bundler.address}`);
    console.log(`Sample Flow Address: ${sampleFlowAddress}`);
    
    // 6. Save deployment info
    const deploymentInfo = {
        network: (await ethers.provider.getNetwork()).name,
        chainId: (await ethers.provider.getNetwork()).chainId,
        timestamp: new Date().toISOString(),
        contracts: {
            flowRootRegistry: flowRootRegistry.address,
            smartAccountImpl: smartAccountImpl.address,
            sampleSmartAccount: smartAccount.address
        },
        configuration: {
            trustedBundler: bundler.address,
            sampleFlowAddress: sampleFlowAddress,
            deployerAddress: deployer.address
        },
        gasUsed: {
            flowRootRegistry: (await flowRootRegistry.deployTransaction.wait()).gasUsed.toString(),
            smartAccountImpl: (await smartAccountImpl.deployTransaction.wait()).gasUsed.toString(),
            proxy: (await proxy.deployTransaction.wait()).gasUsed.toString()
        }
    };

    const fs = require('fs');
    const path = require('path');
    
    const deploymentDir = path.join(__dirname, '../deployments');
    if (!fs.existsSync(deploymentDir)) {
        fs.mkdirSync(deploymentDir, { recursive: true });
    }
    
    const filename = `flow-controlled-${deploymentInfo.network}-${Date.now()}.json`;
    fs.writeFileSync(
        path.join(deploymentDir, filename),
        JSON.stringify(deploymentInfo, null, 2)
    );
    
    console.log(`\n💾 Deployment info saved to: deployments/${filename}`);
    
    // 7. Next steps
    console.log('\n🎯 Next Steps:');
    console.log('1. Deploy FlowKeyRegister.cdc to Flow blockchain');
    console.log('2. Configure bundler service with deployed addresses');
    console.log('3. Update Flow client applications with registry address');
    console.log('4. Test end-to-end flow with sample accounts');
    
    console.log('\n✨ Deployment completed successfully!');
}

// Execute deployment
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('❌ Deployment failed:', error);
        process.exit(1);
    });