// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title FlowRootRegistry
 * @dev Stores latest Merkle roots for Flow accounts, managed by trusted bundler
 * @notice POC implementation with single trusted bundler - see docs for future decentralization approach
 */
contract FlowRootRegistry is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    // Events
    event RootUpdated(
        address indexed flowAddress,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 blockHeight,
        uint256 keyCount,
        address bundler
    );
    
    event BundlerUpdated(address indexed oldBundler, address indexed newBundler);
    event EmergencyRootUpdate(address indexed flowAddress, bytes32 indexed newRoot, address indexed admin);

    // Root storage structure
    struct RootData {
        bytes32 merkleRoot;          // Current Merkle root
        uint256 lastUpdateHeight;    // Flow block height when updated
        uint256 lastUpdateTime;      // EVM timestamp when updated
        uint256 keyCount;            // Number of keys in the tree
        address updatedBy;           // Who updated this root
    }

    // Storage mappings
    mapping(address => RootData) public roots;
    mapping(address => bytes32[]) public rootHistory; // Track root history for debugging
    
    // Bundler configuration
    address public trustedBundler;
    uint256 public maxRootAge = 1 hours; // Maximum age before root is considered stale
    
    // Constants for key validation
    uint8 public constant ECDSA_P256 = 1;
    uint8 public constant ECDSA_SECP256K1 = 2;
    uint8 public constant SHA2_256 = 1;
    uint8 public constant SHA3_256 = 2;

    modifier onlyBundler() {
        require(msg.sender == trustedBundler, "FlowRootRegistry: caller is not the trusted bundler");
        _;
    }

    modifier validFlowAddress(address flowAddress) {
        require(flowAddress != address(0), "FlowRootRegistry: invalid Flow address");
        _;
    }

    constructor(address _trustedBundler) {
        require(_trustedBundler != address(0), "FlowRootRegistry: invalid bundler address");
        trustedBundler = _trustedBundler;
    }

    /**
     * @dev Update Merkle root for a Flow address (called by trusted bundler)
     * @param flowAddress Flow account address
     * @param newRoot New Merkle root
     * @param blockHeight Flow block height when keys were fetched
     * @param keyCount Number of keys in the Merkle tree
     */
    function updateRoot(
        address flowAddress,
        bytes32 newRoot,
        uint256 blockHeight,
        uint256 keyCount
    ) external onlyBundler nonReentrant validFlowAddress(flowAddress) {
        require(newRoot != bytes32(0), "FlowRootRegistry: invalid root");
        require(blockHeight > 0, "FlowRootRegistry: invalid block height");
        require(keyCount > 0, "FlowRootRegistry: key count must be positive");

        RootData storage rootData = roots[flowAddress];
        
        // Ensure we're not going backwards in time (prevent replay attacks)
        require(
            blockHeight >= rootData.lastUpdateHeight,
            "FlowRootRegistry: block height must not decrease"
        );

        // Store old root for event
        bytes32 oldRoot = rootData.merkleRoot;

        // Update root data
        rootData.merkleRoot = newRoot;
        rootData.lastUpdateHeight = blockHeight;
        rootData.lastUpdateTime = block.timestamp;
        rootData.keyCount = keyCount;
        rootData.updatedBy = msg.sender;

        // Store in history
        rootHistory[flowAddress].push(newRoot);

        emit RootUpdated(flowAddress, oldRoot, newRoot, blockHeight, keyCount, msg.sender);
    }

    /**
     * @dev Get current Merkle root for a Flow address
     * @param flowAddress Flow account address
     * @return Current Merkle root
     */
    function getRoot(address flowAddress) external view validFlowAddress(flowAddress) returns (bytes32) {
        return roots[flowAddress].merkleRoot;
    }

    /**
     * @dev Get complete root data for a Flow address
     * @param flowAddress Flow account address
     * @return RootData struct with all information
     */
    function getRootData(address flowAddress) external view validFlowAddress(flowAddress) returns (RootData memory) {
        return roots[flowAddress];
    }

    /**
     * @dev Check if root is fresh (not stale)
     * @param flowAddress Flow account address
     * @return true if root is fresh, false if stale
     */
    function isRootFresh(address flowAddress) external view validFlowAddress(flowAddress) returns (bool) {
        RootData memory rootData = roots[flowAddress];
        return (block.timestamp - rootData.lastUpdateTime) <= maxRootAge;
    }

    /**
     * @dev Get root update history for a Flow address
     * @param flowAddress Flow account address
     * @return Array of historical roots
     */
    function getRootHistory(address flowAddress) external view validFlowAddress(flowAddress) returns (bytes32[] memory) {
        return rootHistory[flowAddress];
    }

    /**
     * @dev Verify Merkle proof for a given leaf and root
     * @param leaf Leaf node to verify
     * @param proof Merkle proof array
     * @param root Merkle root to verify against
     * @return true if proof is valid
     */
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] memory proof,
        bytes32 root
    ) public pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == root;
    }

    /**
     * @dev Create leaf hash from Flow key data
     * @param publicKey Public key (hex string without 04 prefix)
     * @param weight Key weight
     * @param hashAlgorithm Hash algorithm ID
     * @param signatureAlgorithm Signature algorithm ID
     * @return Leaf hash for Merkle tree
     */
    function createLeafHash(
        bytes memory publicKey,
        uint256 weight,
        uint8 hashAlgorithm,
        uint8 signatureAlgorithm
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(publicKey, weight, hashAlgorithm, signatureAlgorithm));
    }

    /**
     * @dev Convert public key to address for signature verification
     * @param publicKey Uncompressed public key (64 bytes)
     * @param signatureAlgorithm Signature algorithm (1=P256, 2=secp256k1)
     * @return Ethereum address derived from public key
     */
    function pubkeyToAddress(bytes memory publicKey, uint8 signatureAlgorithm) public pure returns (address) {
        require(publicKey.length == 64, "FlowRootRegistry: invalid public key length");
        require(
            signatureAlgorithm == ECDSA_P256 || signatureAlgorithm == ECDSA_SECP256K1,
            "FlowRootRegistry: unsupported signature algorithm"
        );

        if (signatureAlgorithm == ECDSA_SECP256K1) {
            // For secp256k1, use standard Ethereum address derivation
            return address(uint160(uint256(keccak256(publicKey))));
        } else {
            // For P256, use a different derivation method
            // Note: P256 keys cannot directly create Ethereum addresses
            // This is a simplified approach - may need adjustment based on actual requirements
            return address(uint160(uint256(keccak256(abi.encodePacked("P256:", publicKey)))));
        }
    }

    // Admin functions

    /**
     * @dev Update trusted bundler address (admin only)
     * @param newBundler New bundler address
     */
    function updateBundler(address newBundler) external onlyOwner {
        require(newBundler != address(0), "FlowRootRegistry: invalid bundler address");
        address oldBundler = trustedBundler;
        trustedBundler = newBundler;
        emit BundlerUpdated(oldBundler, newBundler);
    }

    /**
     * @dev Update maximum root age (admin only)
     * @param newMaxAge New maximum age in seconds
     */
    function updateMaxRootAge(uint256 newMaxAge) external onlyOwner {
        require(newMaxAge > 0, "FlowRootRegistry: invalid max age");
        maxRootAge = newMaxAge;
    }

    /**
     * @dev Emergency root update by admin (for recovery scenarios)
     * @param flowAddress Flow account address
     * @param newRoot Emergency root
     */
    function emergencyUpdateRoot(
        address flowAddress,
        bytes32 newRoot
    ) external onlyOwner nonReentrant validFlowAddress(flowAddress) {
        require(newRoot != bytes32(0), "FlowRootRegistry: invalid root");

        RootData storage rootData = roots[flowAddress];
        rootData.merkleRoot = newRoot;
        rootData.lastUpdateTime = block.timestamp;
        rootData.updatedBy = msg.sender;

        emit EmergencyRootUpdate(flowAddress, newRoot, msg.sender);
    }

    /**
     * @dev Get contract version and configuration
     * @return Version string and configuration details
     */
    function getContractInfo() external view returns (
        string memory version,
        address bundler,
        uint256 rootAge,
        uint256 totalFlowAccounts
    ) {
        // Note: totalFlowAccounts would require additional tracking - simplified for POC
        return ("1.0.0-POC", trustedBundler, maxRootAge, 0);
    }
}