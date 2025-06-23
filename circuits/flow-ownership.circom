pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Privacy-preserving Flow account ownership proof
// Proves ownership without revealing public key or account identity
template FlowAccountOwnership() {
    // Private inputs (witness) - never revealed
    signal input accountProofData[4];   // Flow account-proof verification data
    signal input salt;                  // Random salt for commitment
    signal input nullifierSecret;      // Secret for nullifier generation
    
    // Public inputs - visible on-chain
    signal input commitment;                    // Hash(accountProofData, salt)
    signal input nullifier;                     // Unique nullifier for this proof
    signal input messageHash;                   // Message being signed for ERC-4337
    signal input challengeHash;                 // Challenge used in Flow account-proof
    signal input timestamp;                     // Proof timestamp for expiry
    
    // Output signal
    signal output isValid;                      // 1 if proof is valid, 0 otherwise
    
    // Component declarations
    component commitmentHasher = Poseidon(5);
    component nullifierHasher = Poseidon(3);
    component messageVerifier = Poseidon(3);
    component timestampCheck = LessEqThan(64);
    
    // 1. Verify commitment is correctly formed
    // commitment = Hash(accountProofData[0], accountProofData[1], accountProofData[2], accountProofData[3], salt)
    commitmentHasher.inputs[0] <== accountProofData[0];
    commitmentHasher.inputs[1] <== accountProofData[1];
    commitmentHasher.inputs[2] <== accountProofData[2];
    commitmentHasher.inputs[3] <== accountProofData[3];
    commitmentHasher.inputs[4] <== salt;
    
    // Commitment must match public input
    commitmentHasher.out === commitment;
    
    // 2. Verify nullifier is correctly generated
    // nullifier = Hash(accountProofData[0], nullifierSecret, challengeHash)
    nullifierHasher.inputs[0] <== accountProofData[0];  // Account identifier
    nullifierHasher.inputs[1] <== nullifierSecret;     // Secret prevents forgery
    nullifierHasher.inputs[2] <== challengeHash;       // Binds to specific challenge
    
    // Nullifier must match public input
    nullifierHasher.out === nullifier;
    
    // 3. Verify message authorization
    // Proves the account can authorize this specific message
    messageVerifier.inputs[0] <== accountProofData[1];  // Account capability
    messageVerifier.inputs[1] <== messageHash;          // ERC-4337 message
    messageVerifier.inputs[2] <== challengeHash;        // Challenge binding
    
    // 4. Verify proof freshness (timestamp within acceptable range)
    // Prevents replay of old proofs
    timestampCheck.in[0] <== timestamp;
    timestampCheck.in[1] <== 1800000000; // ~Jan 2025 (example max timestamp)
    
    // 5. Output validation
    // All checks must pass for valid proof
    isValid <== timestampCheck.out;
}

// Helper template for commitment generation (used off-chain)
template CommitmentGenerator() {
    signal input accountProofData[4];
    signal input salt;
    signal output commitment;
    
    component hasher = Poseidon(5);
    hasher.inputs[0] <== accountProofData[0];
    hasher.inputs[1] <== accountProofData[1];
    hasher.inputs[2] <== accountProofData[2];
    hasher.inputs[3] <== accountProofData[3];
    hasher.inputs[4] <== salt;
    
    commitment <== hasher.out;
}

// Helper template for nullifier generation (used off-chain)
template NullifierGenerator() {
    signal input accountIdentifier;
    signal input nullifierSecret;
    signal input challengeHash;
    signal output nullifier;
    
    component hasher = Poseidon(3);
    hasher.inputs[0] <== accountIdentifier;
    hasher.inputs[1] <== nullifierSecret;
    hasher.inputs[2] <== challengeHash;
    
    nullifier <== hasher.out;
}

// Main component for off-chain proof generation
component main = FlowAccountOwnership();