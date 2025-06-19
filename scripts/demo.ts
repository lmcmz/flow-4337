#!/usr/bin/env ts-node

/**
 * Flow ZKP + ERC-4337 Demo Script
 * Demonstrates the complete flow from Flow account to EVM operation via ZKP
 */

import { FlowIntegration, FlowAccount } from "../src/flow-integration";
import { ZKPGenerator, CircuitInputs } from "../src/zkp-generator";

async function main() {
  console.log("🚀 Flow ZKP + ERC-4337 Demo Starting...\n");

  // Initialize components
  const flowIntegration = new FlowIntegration();
  const zkpGenerator = new ZKPGenerator();

  try {
    // Step 1: Create Flow Account
    console.log("📝 Step 1: Creating Flow Account");
    const flowAccount = await flowIntegration.createFlowAccount();
    console.log(`✅ Flow Account Created:`);
    console.log(`   Address: ${flowAccount.address}`);
    console.log(`   Public Key: ${flowAccount.publicKey?.slice(0, 20)}...`);
    console.log();

    // Step 2: Prepare Message to Sign
    console.log("📝 Step 2: Preparing Message for ZKP");
    const message = "Transfer 1.0 ETH to 0x742d35Cc6634C0532925a3b8D4f68F4D752b80f7";
    const nonce = Math.floor(Math.random() * 1000000); // Random nonce for demo
    
    console.log(`   Message: "${message}"`);
    console.log(`   Nonce: ${nonce}`);
    console.log();

    // Step 3: Generate ZKP Inputs
    console.log("📝 Step 3: Generating ZKP Inputs");
    const zkpInputs = await flowIntegration.prepareZKPInputs(message, flowAccount, nonce);
    
    console.log(`✅ ZKP Inputs Generated:`);
    console.log(`   Message Hash: ${zkpInputs.messageHash.slice(0, 20)}...`);
    console.log(`   Public Key X: ${zkpInputs.publicKeyX.slice(0, 20)}...`);
    console.log(`   Public Key Y: ${zkpInputs.publicKeyY.slice(0, 20)}...`);
    console.log(`   Account Address: ${zkpInputs.accountAddress.slice(0, 20)}...`);
    console.log(`   Nonce: ${zkpInputs.nonce}`);
    console.log();

    // Step 4: Generate ZK Proof (Mock for demo)
    console.log("📝 Step 4: Generating Zero-Knowledge Proof");
    
    // Check if circuit files exist
    if (zkpGenerator.circuitFilesExist()) {
      console.log("   🔧 Using compiled circuits for proof generation...");
      const zkProof = await zkpGenerator.generateProof(zkpInputs);
      console.log(`   ✅ Real ZK Proof Generated!`);
      console.log(`   Proof Size: ${JSON.stringify(zkProof).length} bytes`);
    } else {
      console.log("   ⚠️  Circuit files not found, using mock proof for demo...");
      const mockProof = zkpGenerator.generateMockProof(zkpInputs);
      console.log(`   ✅ Mock ZK Proof Generated!`);
      console.log(`   Proof Components:`);
      console.log(`     - proof_a: [${mockProof.proof_a[0].slice(0, 10)}..., ${mockProof.proof_a[1].slice(0, 10)}...]`);
      console.log(`     - proof_b: 2x2 matrix`);
      console.log(`     - proof_c: [${mockProof.proof_c[0].slice(0, 10)}..., ${mockProof.proof_c[1].slice(0, 10)}...]`);
      console.log(`     - public inputs: ${mockProof.publicInputs.length} values`);
    }
    console.log();

    // Step 5: Create UserOperation Signature
    console.log("📝 Step 5: Creating ERC-4337 UserOperation");
    const proofComponents = zkpGenerator.generateMockProof(zkpInputs);
    const userOpSignature = zkpGenerator.createUserOperationSignature(proofComponents);
    
    console.log(`✅ UserOperation Created:`);
    console.log(`   Signature Length: ${userOpSignature.length} bytes`);
    console.log(`   Signature: ${userOpSignature.slice(0, 50)}...`);
    console.log();

    // Step 6: Verify Flow Signature (traditional verification)
    console.log("📝 Step 6: Verifying Flow Signature");
    const flowSignature = await flowIntegration.signMessage(message, flowAccount);
    const isValidSignature = flowIntegration.verifySignature(
      message, 
      flowSignature.signature, 
      flowAccount.publicKey!
    );
    
    console.log(`✅ Flow Signature Verification: ${isValidSignature ? '✅ VALID' : '❌ INVALID'}`);
    console.log();

    // Step 7: Summary
    console.log("📝 Step 7: Demo Summary");
    console.log("✅ Successfully demonstrated:");
    console.log("   1. ✅ Flow account creation and key management");
    console.log("   2. ✅ Message signing with Flow account");
    console.log("   3. ✅ ZKP input preparation for circuit");
    console.log("   4. ✅ ZK proof generation (mock/real)");
    console.log("   5. ✅ ERC-4337 UserOperation signature creation");
    console.log("   6. ✅ Flow signature verification");
    console.log();

    // Step 8: Next Steps
    console.log("🔮 Next Steps for Full Implementation:");
    console.log("   1. 🛠️  Compile circom circuits with trusted setup");
    console.log("   2. 🚀 Deploy contracts to Flow EVM testnet");
    console.log("   3. 🧪 Run integration tests with real ZKP");
    console.log("   4. 📱 Build frontend demo application");
    console.log("   5. 🔒 Security audit and optimization");
    console.log();

    console.log("🎉 Demo completed successfully!");
    
  } catch (error) {
    console.error("❌ Demo failed:", error);
    process.exit(1);
  }
}

// Utility function to demonstrate the complete flow
async function demonstrateCompleteFlow() {
  console.log("\n" + "=".repeat(60));
  console.log("🔄 COMPLETE FLOW DEMONSTRATION");
  console.log("=".repeat(60));

  const flowIntegration = new FlowIntegration();
  const zkpGenerator = new ZKPGenerator();

  // Create multiple Flow accounts
  console.log("\n1. Creating multiple Flow accounts...");
  const accounts = await Promise.all([
    flowIntegration.createFlowAccount(),
    flowIntegration.createFlowAccount(),
    flowIntegration.createFlowAccount()
  ]);

  console.log(`   Created ${accounts.length} Flow accounts`);

  // Demonstrate batch operations
  console.log("\n2. Preparing batch ZKP operations...");
  const batchInputs: CircuitInputs[] = [];
  
  for (let i = 0; i < accounts.length; i++) {
    const message = `Batch operation ${i + 1}: Transfer ${i + 1} ETH`;
    const nonce = 1000 + i;
    const zkpInputs = await flowIntegration.prepareZKPInputs(message, accounts[i], nonce);
    batchInputs.push(zkpInputs);
  }

  console.log(`   Prepared ${batchInputs.length} ZKP operations`);

  // Generate batch proofs (mock)
  console.log("\n3. Generating batch ZK proofs...");
  const batchProofs = batchInputs.map(input => zkpGenerator.generateMockProof(input));
  console.log(`   Generated ${batchProofs.length} ZK proofs`);

  // Create UserOperations
  console.log("\n4. Creating batch UserOperations...");
  const userOpSignatures = batchProofs.map(proof => 
    zkpGenerator.createUserOperationSignature(proof)
  );
  console.log(`   Created ${userOpSignatures.length} UserOperation signatures`);

  console.log("\n✅ Batch demonstration completed!");
  console.log(`   Total operations processed: ${accounts.length}`);
  console.log(`   Average signature size: ${Math.round(userOpSignatures.reduce((sum, sig) => sum + sig.length, 0) / userOpSignatures.length)} bytes`);
}

// Run demo
if (require.main === module) {
  main()
    .then(() => demonstrateCompleteFlow())
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}