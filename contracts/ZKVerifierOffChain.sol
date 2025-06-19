// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZKVerifierOffChain
 * @dev Standalone ZK proof verifier for off-chain generated Flow account ownership proofs
 * @notice Verifies ZK proofs WITHOUT connecting to Flow blockchain
 *         Optimized for commitment-based privacy-preserving verification
 */
contract ZKVerifierOffChain {
    using Pairing for *;
    
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    
    // Events
    event VerifyingKeyUpdated(address updatedBy);
    event ProofVerified(bytes32 indexed commitment, bytes32 indexed nullifier);
    event ProofVerificationFailed(bytes32 indexed commitment, bytes32 indexed nullifier);
    
    // State
    VerifyingKey verifyingKey;
    address public owner;
    bool public isInitialized;
    
    // Statistics
    uint256 public totalProofsVerified;
    uint256 public totalVerificationFailures;
    
    // Errors
    error NotOwner();
    error AlreadyInitialized();
    error NotInitialized();
    error InvalidProofStructure();
    error InvalidPublicSignals();
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        _;
    }
    
    modifier whenInitialized() {
        if (!isInitialized) {
            revert NotInitialized();
        }
        _;
    }

    constructor() {
        owner = msg.sender;
        // Initialize with placeholder values for development/testing
        _initializeTestingKey();
    }
    
    /**
     * @dev Initialize verifying key from trusted setup
     * @param vkAlpha Alpha component of verifying key
     * @param vkBeta Beta component of verifying key
     * @param vkGamma Gamma component of verifying key
     * @param vkDelta Delta component of verifying key
     * @param vkGammaAbc Gamma ABC components of verifying key
     */
    function initializeVerifyingKey(
        uint[2] memory vkAlpha,
        uint[2][2] memory vkBeta,
        uint[2][2] memory vkGamma,
        uint[2][2] memory vkDelta,
        uint[2][] memory vkGammaAbc
    ) external onlyOwner {
        if (isInitialized) {
            revert AlreadyInitialized();
        }
        
        verifyingKey.alpha = Pairing.G1Point(vkAlpha[0], vkAlpha[1]);
        verifyingKey.beta = Pairing.G2Point([vkBeta[0][0], vkBeta[0][1]], [vkBeta[1][0], vkBeta[1][1]]);
        verifyingKey.gamma = Pairing.G2Point([vkGamma[0][0], vkGamma[0][1]], [vkGamma[1][0], vkGamma[1][1]]);
        verifyingKey.delta = Pairing.G2Point([vkDelta[0][0], vkDelta[0][1]], [vkDelta[1][0], vkDelta[1][1]]);
        
        delete verifyingKey.gamma_abc;
        for (uint i = 0; i < vkGammaAbc.length; i++) {
            verifyingKey.gamma_abc.push(Pairing.G1Point(vkGammaAbc[i][0], vkGammaAbc[i][1]));
        }
        
        isInitialized = true;
        emit VerifyingKeyUpdated(msg.sender);
    }
    
    /**
     * @dev Verify off-chain generated ZK proof
     * @param proof_a First component of the proof
     * @param proof_b Second component of the proof  
     * @param proof_c Third component of the proof
     * @param publicSignals Public inputs to the circuit
     * @return True if the proof is valid
     */
    function verifyOffChainProof(
        uint[2] memory proof_a,
        uint[2][2] memory proof_b,
        uint[2] memory proof_c,
        uint[] memory publicSignals
    ) public whenInitialized returns (bool) {
        // Validate input structure
        if (publicSignals.length != 5) {
            revert InvalidPublicSignals();
        }
        
        // Extract public signals for logging
        bytes32 commitment = bytes32(publicSignals[0]);
        bytes32 nullifier = bytes32(publicSignals[1]);
        // bytes32 messageHash = bytes32(publicSignals[2]);
        // bytes32 challengeHash = bytes32(publicSignals[3]);
        // uint256 timestamp = publicSignals[4];
        
        try {
            // Construct proof
            Proof memory proof;
            proof.a = Pairing.G1Point(proof_a[0], proof_a[1]);
            proof.b = Pairing.G2Point([proof_b[0][0], proof_b[0][1]], [proof_b[1][0], proof_b[1][1]]);
            proof.c = Pairing.G1Point(proof_c[0], proof_c[1]);
            
            // Verify proof
            bool isValid = verify(publicSignals, proof);
            
            if (isValid) {
                totalProofsVerified++;
                emit ProofVerified(commitment, nullifier);
            } else {
                totalVerificationFailures++;
                emit ProofVerificationFailed(commitment, nullifier);
            }
            
            return isValid;
        } catch {
            totalVerificationFailures++;
            emit ProofVerificationFailed(commitment, nullifier);
            return false;
        }
    }
    
    /**
     * @dev Simplified proof verification for testing (when real verifying key is not available)
     * @param proof_a First component of the proof
     * @param proof_b Second component of the proof  
     * @param proof_c Third component of the proof
     * @param publicSignals Public inputs to the circuit
     * @return True if the proof structure is valid (for testing)
     */
    function verifyProofSimple(
        uint[2] memory proof_a,
        uint[2][2] memory proof_b,
        uint[2] memory proof_c,
        uint[] memory publicSignals
    ) public pure returns (bool) {
        // Simple validation for development/testing
        if (publicSignals.length != 5) return false;
        if (proof_a[0] == 0 && proof_a[1] == 0) return false;
        if (proof_c[0] == 0 && proof_c[1] == 0) return false;
        
        // Check that public signals are reasonable
        if (publicSignals[0] == 0) return false; // commitment
        if (publicSignals[1] == 0) return false; // nullifier
        if (publicSignals[4] == 0) return false; // timestamp
        
        return true;
    }
    
    /**
     * @dev Internal verification function using pairing
     */
    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey;
        require(input.length + 1 == vk.gamma_abc.length, "Invalid input length");
        
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field, "Input out of field");
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        
        // Verify pairing equation
        return Pairing.pairing(
            Pairing.negate(proof.a),
            proof.b,
            vk.alpha,
            vk.beta,
            vk_x,
            vk.gamma,
            proof.c,
            vk.delta
        );
    }
    
    /**
     * @dev Batch verify multiple proofs
     * @param proofs Array of proof components
     * @param publicSignalsArray Array of public signals for each proof
     * @return results Array of verification results
     */
    function batchVerifyProofs(
        uint[2][] memory proof_a_array,
        uint[2][2][] memory proof_b_array,
        uint[2][] memory proof_c_array,
        uint[][] memory publicSignalsArray
    ) external whenInitialized returns (bool[] memory results) {
        require(
            proof_a_array.length == proof_b_array.length &&
            proof_b_array.length == proof_c_array.length &&
            proof_c_array.length == publicSignalsArray.length,
            "Array length mismatch"
        );
        
        results = new bool[](proof_a_array.length);
        
        for (uint i = 0; i < proof_a_array.length; i++) {
            results[i] = verifyOffChainProof(
                proof_a_array[i],
                proof_b_array[i],
                proof_c_array[i],
                publicSignalsArray[i]
            );
        }
        
        return results;
    }
    
    /**
     * @dev Get verification statistics
     * @return totalVerified Total proofs verified successfully
     * @return totalFailed Total verification failures
     * @return successRate Success rate (in basis points, 10000 = 100%)
     */
    function getVerificationStats() external view returns (
        uint256 totalVerified,
        uint256 totalFailed,
        uint256 successRate
    ) {
        totalVerified = totalProofsVerified;
        totalFailed = totalVerificationFailures;
        
        uint256 total = totalVerified + totalFailed;
        if (total == 0) {
            successRate = 0;
        } else {
            successRate = (totalVerified * 10000) / total;
        }
    }
    
    /**
     * @dev Initialize testing verifying key (for development)
     */
    function _initializeTestingKey() private {
        // Placeholder verifying key for testing
        verifyingKey.alpha = Pairing.G1Point(
            0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
            0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321
        );
        verifyingKey.beta = Pairing.G2Point(
            [0x1111111111111111111111111111111111111111111111111111111111111111,
             0x2222222222222222222222222222222222222222222222222222222222222222],
            [0x3333333333333333333333333333333333333333333333333333333333333333,
             0x4444444444444444444444444444444444444444444444444444444444444444]
        );
        verifyingKey.gamma = Pairing.G2Point(
            [0x5555555555555555555555555555555555555555555555555555555555555555,
             0x6666666666666666666666666666666666666666666666666666666666666666],
            [0x7777777777777777777777777777777777777777777777777777777777777777,
             0x8888888888888888888888888888888888888888888888888888888888888888]
        );
        verifyingKey.delta = Pairing.G2Point(
            [0x9999999999999999999999999999999999999999999999999999999999999999,
             0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa],
            [0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,
             0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc]
        );
        
        // Initialize gamma_abc with 6 elements (5 public inputs + 1)
        verifyingKey.gamma_abc = new Pairing.G1Point[](6);
        for (uint i = 0; i < 6; i++) {
            verifyingKey.gamma_abc[i] = Pairing.G1Point(
                uint256(keccak256(abi.encodePacked("gamma_abc", i))) % Pairing.PRIME_Q,
                uint256(keccak256(abi.encodePacked("gamma_abc", i, "y"))) % Pairing.PRIME_Q
            );
        }
        
        isInitialized = true;
    }
    
    /**
     * @dev Update owner
     * @param newOwner New owner address
     */
    function updateOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}

/**
 * @dev Pairing library for elliptic curve operations
 */
library Pairing {
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    struct G1Point {
        uint X;
        uint Y;
    }
    
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }
    
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
    }
    
    function addition(G1Point memory p1, G1Point memory p2) pure internal returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }
        require(success, "Pairing addition failed");
    }
    
    function scalar_mul(G1Point memory p, uint s) pure internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success, "Pairing scalar multiplication failed");
    }
    
    function pairing(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2,
                    G1Point memory c1, G2Point memory c2, G1Point memory d1, G2Point memory d2) 
                    pure internal returns (bool) {
        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        uint inputSize = 24;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < 4; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }
        require(success, "Pairing verification failed");
        return out[0] != 0;
    }
}