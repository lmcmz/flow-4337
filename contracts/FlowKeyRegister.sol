// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title FlowKeyRegister
 * @dev EVM-side registry for Flow account keys with admin override capabilities
 * @notice Stores Flow account keys on EVM for efficient bundler access and Merkle tree generation
 */
contract FlowKeyRegister is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    // Events
    event KeysUpdated(
        address indexed flowAddress,
        uint256 keyCount,
        uint256 totalWeight,
        uint256 blockHeight,
        address indexed updatedBy
    );
    
    event BundlerUpdated(address indexed oldBundler, address indexed newBundler);
    event AdminOverride(address indexed flowAddress, address indexed admin, string reason);
    event KeyRegistryCleared(address indexed flowAddress, address indexed admin);

    // KeyInfo structure containing all Flow key metadata
    struct KeyInfo {
        bytes publicKey;        // 64 bytes uncompressed, no 04 prefix
        uint256 weight;         // Flow key weight (0-1000)
        uint8 hashAlgorithm;    // Hash algorithm ID (1=SHA2_256, 2=SHA3_256)
        uint8 signatureAlgorithm; // Signature algorithm ID (1=ECDSA_P256, 2=ECDSA_secp256k1)
        bool isRevoked;         // Key revocation status
        uint256 keyIndex;       // Original Flow key index
    }

    // Flow account state tracking
    struct FlowAccountState {
        KeyInfo[] keys;         // Array of keys for this Flow account
        uint256 totalWeight;    // Sum of all non-revoked key weights
        uint256 lastUpdateHeight; // Flow block height when last updated
        uint256 lastUpdateTime; // EVM timestamp when last updated
        address lastUpdatedBy;  // Who performed the last update
        bool exists;            // Whether this account has been registered
    }

    // Storage mappings
    mapping(address => FlowAccountState) public flowAccounts;
    mapping(address => bool) public authorizedBundlers;
    
    // Configuration
    address public primaryBundler;
    uint256 public maxKeysPerAccount = 50; // Prevent gas limit issues
    uint256 public constant FLOW_WEIGHT_THRESHOLD = 1000; // Flow's 100% threshold

    // Constants for signature algorithms
    uint8 public constant ECDSA_P256 = 1;
    uint8 public constant ECDSA_SECP256K1 = 2;
    uint8 public constant SHA2_256 = 1;
    uint8 public constant SHA3_256 = 2;

    modifier onlyAuthorizedBundler() {
        require(
            authorizedBundlers[msg.sender] || msg.sender == primaryBundler,
            "FlowKeyRegister: unauthorized bundler"
        );
        _;
    }

    modifier validFlowAddress(address flowAddress) {
        require(flowAddress != address(0), "FlowKeyRegister: invalid Flow address");
        _;
    }

    constructor(address _primaryBundler) {
        require(_primaryBundler != address(0), "FlowKeyRegister: invalid bundler address");
        primaryBundler = _primaryBundler;
        authorizedBundlers[_primaryBundler] = true;
    }

    /**
     * @dev Update keys for a Flow address (called by authorized bundler)
     * @param flowAddress Flow account address
     * @param keys Array of KeyInfo structs
     * @param blockHeight Flow block height when keys were fetched
     */
    function updateKeys(
        address flowAddress,
        KeyInfo[] calldata keys,
        uint256 blockHeight
    ) external onlyAuthorizedBundler nonReentrant validFlowAddress(flowAddress) {
        require(keys.length > 0, "FlowKeyRegister: empty keys array");
        require(keys.length <= maxKeysPerAccount, "FlowKeyRegister: too many keys");
        require(blockHeight > 0, "FlowKeyRegister: invalid block height");

        FlowAccountState storage account = flowAccounts[flowAddress];
        
        // Ensure we're not going backwards in time
        require(
            blockHeight >= account.lastUpdateHeight,
            "FlowKeyRegister: block height must not decrease"
        );

        // Validate and calculate total weight
        uint256 totalWeight = 0;
        for (uint256 i = 0; i < keys.length; i++) {
            require(_validateKeyInfo(keys[i]), "FlowKeyRegister: invalid key info");
            
            if (!keys[i].isRevoked) {
                totalWeight += keys[i].weight;
            }
        }

        // Clear existing keys and add new ones
        delete account.keys;
        for (uint256 i = 0; i < keys.length; i++) {
            account.keys.push(keys[i]);
        }

        // Update account state
        account.totalWeight = totalWeight;
        account.lastUpdateHeight = blockHeight;
        account.lastUpdateTime = block.timestamp;
        account.lastUpdatedBy = msg.sender;
        account.exists = true;

        emit KeysUpdated(flowAddress, keys.length, totalWeight, blockHeight, msg.sender);
    }

    /**
     * @dev Get all keys for a Flow address
     * @param flowAddress Flow account address
     * @return keys Array of KeyInfo structs
     */
    function getKeys(address flowAddress) external view validFlowAddress(flowAddress) returns (KeyInfo[] memory keys) {
        FlowAccountState storage account = flowAccounts[flowAddress];
        require(account.exists, "FlowKeyRegister: Flow address not registered");
        return account.keys;
    }

    /**
     * @dev Get active (non-revoked) keys for a Flow address
     * @param flowAddress Flow account address
     * @return activeKeys Array of active KeyInfo structs
     */
    function getActiveKeys(address flowAddress) external view validFlowAddress(flowAddress) returns (KeyInfo[] memory activeKeys) {
        FlowAccountState storage account = flowAccounts[flowAddress];
        require(account.exists, "FlowKeyRegister: Flow address not registered");

        // Count active keys first
        uint256 activeCount = 0;
        for (uint256 i = 0; i < account.keys.length; i++) {
            if (!account.keys[i].isRevoked) {
                activeCount++;
            }
        }

        // Create array of active keys
        activeKeys = new KeyInfo[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < account.keys.length; i++) {
            if (!account.keys[i].isRevoked) {
                activeKeys[index] = account.keys[i];
                index++;
            }
        }

        return activeKeys;
    }

    /**
     * @dev Get Flow account state
     * @param flowAddress Flow account address
     * @return keyCount Number of keys
     * @return totalWeight Sum of active key weights
     * @return lastUpdateHeight Last Flow block height
     * @return lastUpdateTime Last EVM timestamp
     * @return exists Whether account is registered
     */
    function getAccountState(address flowAddress) external view validFlowAddress(flowAddress) returns (
        uint256 keyCount,
        uint256 totalWeight,
        uint256 lastUpdateHeight,
        uint256 lastUpdateTime,
        bool exists
    ) {
        FlowAccountState storage account = flowAccounts[flowAddress];
        return (
            account.keys.length,
            account.totalWeight,
            account.lastUpdateHeight,
            account.lastUpdateTime,
            account.exists
        );
    }

    /**
     * @dev Check if a Flow address has sufficient key weight for operations
     * @param flowAddress Flow account address
     * @return hasSufficientWeight True if total weight >= FLOW_WEIGHT_THRESHOLD
     */
    function hasSufficientWeight(address flowAddress) external view validFlowAddress(flowAddress) returns (bool) {
        FlowAccountState storage account = flowAccounts[flowAddress];
        return account.exists && account.totalWeight >= FLOW_WEIGHT_THRESHOLD;
    }

    /**
     * @dev Create hash for a KeyInfo struct (used for Merkle tree leaves)
     * @param keyInfo KeyInfo struct to hash
     * @return leafHash Hash of the KeyInfo struct
     */
    function createKeyInfoHash(KeyInfo memory keyInfo) public pure returns (bytes32 leafHash) {
        return keccak256(abi.encode(
            keyInfo.publicKey,
            keyInfo.weight,
            keyInfo.hashAlgorithm,
            keyInfo.signatureAlgorithm,
            keyInfo.isRevoked,
            keyInfo.keyIndex
        ));
    }

    /**
     * @dev Get KeyInfo hashes for Merkle tree construction
     * @param flowAddress Flow account address
     * @return hashes Array of KeyInfo hashes
     */
    function getKeyInfoHashes(address flowAddress) external view validFlowAddress(flowAddress) returns (bytes32[] memory hashes) {
        FlowAccountState storage account = flowAccounts[flowAddress];
        require(account.exists, "FlowKeyRegister: Flow address not registered");

        hashes = new bytes32[](account.keys.length);
        for (uint256 i = 0; i < account.keys.length; i++) {
            hashes[i] = createKeyInfoHash(account.keys[i]);
        }

        return hashes;
    }

    /**
     * @dev Validate KeyInfo structure
     * @param keyInfo KeyInfo to validate
     * @return isValid True if valid
     */
    function _validateKeyInfo(KeyInfo calldata keyInfo) internal pure returns (bool) {
        // Validate public key length (64 bytes)
        if (keyInfo.publicKey.length != 64) {
            return false;
        }

        // Validate weight (0-1000)
        if (keyInfo.weight > 1000) {
            return false;
        }

        // Validate hash algorithm
        if (keyInfo.hashAlgorithm != SHA2_256 && keyInfo.hashAlgorithm != SHA3_256) {
            return false;
        }

        // Validate signature algorithm
        if (keyInfo.signatureAlgorithm != ECDSA_P256 && keyInfo.signatureAlgorithm != ECDSA_SECP256K1) {
            return false;
        }

        return true;
    }

    // Admin functions

    /**
     * @dev Admin override: manually update keys for a Flow address
     * @param flowAddress Flow account address
     * @param keys Array of KeyInfo structs
     * @param reason Reason for admin override
     */
    function adminUpdateKeys(
        address flowAddress,
        KeyInfo[] calldata keys,
        string calldata reason
    ) external onlyOwner nonReentrant validFlowAddress(flowAddress) {
        require(keys.length > 0, "FlowKeyRegister: empty keys array");
        require(keys.length <= maxKeysPerAccount, "FlowKeyRegister: too many keys");
        require(bytes(reason).length > 0, "FlowKeyRegister: reason required");

        FlowAccountState storage account = flowAccounts[flowAddress];

        // Validate and calculate total weight
        uint256 totalWeight = 0;
        for (uint256 i = 0; i < keys.length; i++) {
            require(_validateKeyInfo(keys[i]), "FlowKeyRegister: invalid key info");
            
            if (!keys[i].isRevoked) {
                totalWeight += keys[i].weight;
            }
        }

        // Clear existing keys and add new ones
        delete account.keys;
        for (uint256 i = 0; i < keys.length; i++) {
            account.keys.push(keys[i]);
        }

        // Update account state
        account.totalWeight = totalWeight;
        account.lastUpdateTime = block.timestamp;
        account.lastUpdatedBy = msg.sender;
        account.exists = true;

        emit AdminOverride(flowAddress, msg.sender, reason);
        emit KeysUpdated(flowAddress, keys.length, totalWeight, 0, msg.sender);
    }

    /**
     * @dev Admin override: clear all keys for a Flow address
     * @param flowAddress Flow account address
     * @param reason Reason for clearing
     */
    function adminClearKeys(
        address flowAddress,
        string calldata reason
    ) external onlyOwner validFlowAddress(flowAddress) {
        require(bytes(reason).length > 0, "FlowKeyRegister: reason required");

        FlowAccountState storage account = flowAccounts[flowAddress];
        delete account.keys;
        account.totalWeight = 0;
        account.lastUpdateTime = block.timestamp;
        account.lastUpdatedBy = msg.sender;
        account.exists = false;

        emit KeyRegistryCleared(flowAddress, msg.sender);
        emit AdminOverride(flowAddress, msg.sender, reason);
    }

    /**
     * @dev Update primary bundler
     * @param newBundler New primary bundler address
     */
    function updatePrimaryBundler(address newBundler) external onlyOwner {
        require(newBundler != address(0), "FlowKeyRegister: invalid bundler address");
        
        address oldBundler = primaryBundler;
        authorizedBundlers[oldBundler] = false;
        
        primaryBundler = newBundler;
        authorizedBundlers[newBundler] = true;
        
        emit BundlerUpdated(oldBundler, newBundler);
    }

    /**
     * @dev Add authorized bundler
     * @param bundler Bundler address to authorize
     */
    function addAuthorizedBundler(address bundler) external onlyOwner {
        require(bundler != address(0), "FlowKeyRegister: invalid bundler address");
        authorizedBundlers[bundler] = true;
    }

    /**
     * @dev Remove authorized bundler
     * @param bundler Bundler address to remove
     */
    function removeAuthorizedBundler(address bundler) external onlyOwner {
        require(bundler != primaryBundler, "FlowKeyRegister: cannot remove primary bundler");
        authorizedBundlers[bundler] = false;
    }

    /**
     * @dev Update maximum keys per account
     * @param newMax New maximum
     */
    function updateMaxKeysPerAccount(uint256 newMax) external onlyOwner {
        require(newMax > 0 && newMax <= 100, "FlowKeyRegister: invalid max keys");
        maxKeysPerAccount = newMax;
    }

    /**
     * @dev Get contract configuration
     * @return primaryBundlerAddr Primary bundler address
     * @return maxKeys Maximum keys per account
     * @return weightThreshold Flow weight threshold
     */
    function getConfiguration() external view returns (
        address primaryBundlerAddr,
        uint256 maxKeys,
        uint256 weightThreshold
    ) {
        return (primaryBundler, maxKeysPerAccount, FLOW_WEIGHT_THRESHOLD);
    }
}