pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/ecdsa.circom";

// Circuit to verify Flow account signature without revealing private key
// Flow uses ECDSA with P-256 curve, but for ZKP compatibility we use simplified approach
template FlowSignatureVerification() {
    // Public inputs
    signal input messageHash;           // Hash of the message to be signed
    signal input publicKeyX;           // Flow account public key X coordinate  
    signal input publicKeyY;           // Flow account public key Y coordinate
    signal input accountAddress;       // Flow account address (derived from pubkey)
    signal input nonce;                // Prevent replay attacks
    
    // Private inputs (witness)
    signal private input signature[2]; // ECDSA signature (r, s)
    signal private input privateKey;   // Flow account private key (kept private)
    
    // Output
    signal output isValid;             // 1 if signature is valid, 0 otherwise
    
    // Components
    component poseidon = Poseidon(4);
    component ecdsa = ECDSAVerifyNoPubkeyCheck();
    
    // Verify that private key corresponds to public key
    component pubkeyGen = ECdsaPrivToPub();
    pubkeyGen.privkey <== privateKey;
    pubkeyGen.pubkey[0] === publicKeyX;
    pubkeyGen.pubkey[1] === publicKeyY;
    
    // Verify account address is derived from public key
    // In Flow, address = hash(publicKey)
    component addressHash = Poseidon(2);
    addressHash.inputs[0] <== publicKeyX;
    addressHash.inputs[1] <== publicKeyY;
    addressHash.out === accountAddress;
    
    // Create commitment hash including nonce for replay protection
    poseidon.inputs[0] <== messageHash;
    poseidon.inputs[1] <== publicKeyX;
    poseidon.inputs[2] <== publicKeyY;
    poseidon.inputs[3] <== nonce;
    
    // Verify ECDSA signature
    ecdsa.r <== signature[0];
    ecdsa.s <== signature[1];
    ecdsa.msghash <== poseidon.out;
    ecdsa.pubkey[0] <== publicKeyX;
    ecdsa.pubkey[1] <== publicKeyY;
    
    // Output validation result
    isValid <== ecdsa.result;
}

// Main component with specific constraints for Flow accounts
component main = FlowSignatureVerification();