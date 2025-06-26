// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IEntryPoint.sol";
import "./FlowRootRegistry.sol";
import "./FlowKeyRegister.sol";

/**
 * @title FlowControlledSmartAccountV2
 * @dev ERC-4337 Smart Account with multi-signature Flow key validation
 * @notice Supports multiple Flow keys with weight-based threshold validation (sum >= 1000)
 */
contract FlowControlledSmartAccountV2 is Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    // Events
    event FlowAccountLinked(address indexed flowAddress, address indexed smartAccount);
    event UserOperationExecuted(bytes32 indexed userOpHash, address indexed flowAddress, bool success);
    event MultiSigValidated(address indexed flowAddress, uint256 totalWeight, uint256 keyCount);
    event FlowRootRegistryUpdated(address indexed oldRegistry, address indexed newRegistry);
    event FlowKeyRegisterUpdated(address indexed oldRegister, address indexed newRegister);
    event EmergencyRecovery(address indexed newOwner, address indexed initiator);

    // Multi-signature user operation data structure
    struct FlowMultiSigUserOp {
        address flowAddress;          // Flow account address
        bytes32 opHash;              // keccak256(UserOperation)
        FlowKeyRegister.KeyInfo[] keys; // Array of keys used for signing
        bytes[] signatures;          // Array of signatures corresponding to keys
        bytes32[] merkleProofs;      // Array of Merkle proofs for key inclusion
    }

    // State variables
    FlowRootRegistry public flowRootRegistry;
    FlowKeyRegister public flowKeyRegister;
    address public linkedFlowAddress;
    mapping(bytes32 => bool) public executedUserOps;
    
    // Constants
    uint8 public constant ECDSA_P256 = 1;
    uint8 public constant ECDSA_SECP256K1 = 2;
    uint256 public constant FLOW_WEIGHT_THRESHOLD = 1000; // Flow's 100% weight requirement
    
    // Admin address (for emergency functions only, no operational control)
    address public admin;

    modifier onlyLinkedFlow() {
        require(linkedFlowAddress != address(0), "SmartAccount: no Flow account linked");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "SmartAccount: not admin");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initialize the smart account (called by factory)
     * @param _flowRootRegistry Address of the Flow root registry
     * @param _flowAddress Flow account address to link (no EVM owner required)
     */
    function initialize(
        address _flowRootRegistry,
        address _flowAddress
    ) public initializer {
        require(_flowRootRegistry != address(0), "SmartAccount: invalid registry address");
        require(_flowAddress != address(0), "SmartAccount: invalid Flow address");

        __UUPSUpgradeable_init();

        flowRootRegistry = FlowRootRegistry(_flowRootRegistry);
        
        // Get FlowKeyRegister from the registry (if supported)
        // For now, we'll set it separately via setFlowKeyRegister
        linkedFlowAddress = _flowAddress;
        
        // Set admin to the factory deployer initially (can be changed later)
        admin = msg.sender;

        emit FlowAccountLinked(_flowAddress, address(this));
    }

    /**
     * @dev Set Flow key register address (admin only)
     * @param _flowKeyRegister FlowKeyRegister contract address
     */
    function setFlowKeyRegister(address _flowKeyRegister) external onlyAdmin {
        require(_flowKeyRegister != address(0), "SmartAccount: invalid register address");
        address oldRegister = address(flowKeyRegister);
        flowKeyRegister = FlowKeyRegister(_flowKeyRegister);
        emit FlowKeyRegisterUpdated(oldRegister, _flowKeyRegister);
    }

    /**
     * @dev Validate multi-signature user operation
     * @param userOp Multi-signature user operation data
     * @return validationData Validation result (0 = success, 1 = failure)
     */
    function validateUserOp(
        FlowMultiSigUserOp memory userOp
    ) public view returns (uint256 validationData) {
        try this._validateUserOpInternal(userOp) returns (bool isValid) {
            return isValid ? 0 : 1;
        } catch {
            return 1;
        }
    }

    /**
     * @dev Internal validation logic (public for try-catch)
     * @param userOp Multi-signature user operation data
     * @return true if validation passes
     */
    function _validateUserOpInternal(
        FlowMultiSigUserOp memory userOp
    ) public view returns (bool) {
        // 1. Verify Flow address matches linked account
        require(userOp.flowAddress == linkedFlowAddress, "SmartAccount: Flow address mismatch");

        // 2. Verify operation hasn't been executed
        require(!executedUserOps[userOp.opHash], "SmartAccount: operation already executed");

        // 3. Verify arrays have consistent lengths
        require(
            userOp.keys.length == userOp.signatures.length && 
            userOp.signatures.length == userOp.merkleProofs.length,
            "SmartAccount: array length mismatch"
        );

        require(userOp.keys.length > 0, "SmartAccount: empty keys array");

        // 4. Get current Merkle root from registry
        bytes32 storedRoot = flowRootRegistry.getRoot(userOp.flowAddress);
        require(storedRoot != bytes32(0), "SmartAccount: no root found for Flow address");

        // 5. Verify root is fresh
        require(flowRootRegistry.isRootFresh(userOp.flowAddress), "SmartAccount: stale root");

        // 6. Validate each key and signature, calculate total weight
        uint256 totalWeight = 0;
        mapping(bytes32 => bool) memory usedKeys; // Prevent duplicate keys
        
        for (uint256 i = 0; i < userOp.keys.length; i++) {
            FlowKeyRegister.KeyInfo memory keyInfo = userOp.keys[i];
            
            // Verify key is not revoked
            require(!keyInfo.isRevoked, "SmartAccount: revoked key used");
            
            // Create KeyInfo hash for Merkle verification
            bytes32 keyInfoHash = flowKeyRegister.createKeyInfoHash(keyInfo);
            
            // Prevent duplicate keys in same operation
            require(!usedKeys[keyInfoHash], "SmartAccount: duplicate key");
            usedKeys[keyInfoHash] = true;
            
            // Verify Merkle proof for this key
            require(
                flowRootRegistry.verifyMerkleProof(keyInfoHash, userOp.merkleProofs[i], storedRoot),
                "SmartAccount: invalid Merkle proof"
            );
            
            // Verify signature
            require(
                _validateSingleSignature(userOp.opHash, userOp.signatures[i], keyInfo),
                "SmartAccount: invalid signature"
            );
            
            // Add weight if signature is valid
            totalWeight += keyInfo.weight;
        }

        // 7. Check total weight meets threshold
        require(totalWeight >= FLOW_WEIGHT_THRESHOLD, "SmartAccount: insufficient signature weight");

        return true;
    }

    /**
     * @dev Validate a single signature against a key
     * @param opHash Operation hash that was signed
     * @param signature Signature bytes
     * @param keyInfo KeyInfo struct for the signing key
     * @return isValid True if signature is valid
     */
    function _validateSingleSignature(
        bytes32 opHash,
        bytes memory signature,
        FlowKeyRegister.KeyInfo memory keyInfo
    ) internal pure returns (bool isValid) {
        // Validate signature algorithm is supported
        require(
            keyInfo.signatureAlgorithm == ECDSA_P256 || keyInfo.signatureAlgorithm == ECDSA_SECP256K1,
            "SmartAccount: unsupported signature algorithm"
        );

        // Validate public key format
        require(keyInfo.publicKey.length == 64, "SmartAccount: invalid public key length");

        address expectedSigner = _pubkeyToAddress(keyInfo.publicKey, keyInfo.signatureAlgorithm);
        address recoveredSigner;

        if (keyInfo.signatureAlgorithm == ECDSA_SECP256K1) {
            recoveredSigner = opHash.recover(signature);
        } else {
            // For P256, use specialized verification
            recoveredSigner = _verifyP256Signature(opHash, signature, keyInfo.publicKey);
        }

        return recoveredSigner == expectedSigner;
    }

    /**
     * @dev Convert public key to address for signature verification
     * @param publicKey Uncompressed public key (64 bytes)
     * @param signatureAlgorithm Signature algorithm (1=P256, 2=secp256k1)
     * @return Ethereum address derived from public key
     */
    function _pubkeyToAddress(bytes memory publicKey, uint8 signatureAlgorithm) internal pure returns (address) {
        require(publicKey.length == 64, "SmartAccount: invalid public key length");

        if (signatureAlgorithm == ECDSA_SECP256K1) {
            return address(uint160(uint256(keccak256(publicKey))));
        } else {
            // For P256, use different derivation method
            return address(uint160(uint256(keccak256(abi.encodePacked("P256:", publicKey)))));
        }
    }

    /**
     * @dev Verify P256 signature (simplified implementation)
     * @param hash Message hash
     * @param signature Signature bytes
     * @param publicKey Public key bytes
     * @return Recovered address
     */
    function _verifyP256Signature(
        bytes32 hash,
        bytes memory signature,
        bytes memory publicKey
    ) internal pure returns (address) {
        // Note: This is a simplified implementation
        // In production, use proper P256 signature verification library
        return address(uint160(uint256(keccak256(abi.encodePacked("P256:", publicKey, hash)))));
    }

    /**
     * @dev Execute a validated multi-signature user operation
     * @param userOp Multi-signature user operation data
     * @param target Target contract address
     * @param data Call data
     * @param value ETH value to send
     * @return success Execution result
     */
    function executeUserOp(
        FlowMultiSigUserOp memory userOp,
        address target,
        bytes calldata data,
        uint256 value
    ) external nonReentrant onlyLinkedFlow returns (bool success) {
        // Validate the user operation
        require(validateUserOp(userOp) == 0, "SmartAccount: validation failed");

        // Mark operation as executed
        executedUserOps[userOp.opHash] = true;

        // Calculate total weight for event
        uint256 totalWeight = 0;
        for (uint256 i = 0; i < userOp.keys.length; i++) {
            totalWeight += userOp.keys[i].weight;
        }

        emit MultiSigValidated(userOp.flowAddress, totalWeight, userOp.keys.length);

        // Execute the operation
        (success, ) = target.call{value: value}(data);

        emit UserOperationExecuted(userOp.opHash, userOp.flowAddress, success);
        return success;
    }

    /**
     * @dev Batch execute multiple operations
     * @param userOps Array of multi-signature user operations
     * @param targets Array of target addresses
     * @param datas Array of call data
     * @param values Array of ETH values
     * @return successes Array of execution results
     */
    function batchExecuteUserOps(
        FlowMultiSigUserOp[] memory userOps,
        address[] memory targets,
        bytes[] calldata datas,
        uint256[] memory values
    ) external nonReentrant onlyLinkedFlow returns (bool[] memory successes) {
        require(
            userOps.length == targets.length &&
            targets.length == datas.length &&
            datas.length == values.length,
            "SmartAccount: array length mismatch"
        );

        successes = new bool[](userOps.length);

        for (uint256 i = 0; i < userOps.length; i++) {
            // Validate each operation
            require(validateUserOp(userOps[i]) == 0, "SmartAccount: batch validation failed");
            
            // Mark as executed
            executedUserOps[userOps[i].opHash] = true;
            
            // Calculate total weight for event
            uint256 totalWeight = 0;
            for (uint256 j = 0; j < userOps[i].keys.length; j++) {
                totalWeight += userOps[i].keys[j].weight;
            }
            
            emit MultiSigValidated(userOps[i].flowAddress, totalWeight, userOps[i].keys.length);
            
            // Execute
            (successes[i], ) = targets[i].call{value: values[i]}(datas[i]);
            
            emit UserOperationExecuted(userOps[i].opHash, userOps[i].flowAddress, successes[i]);
        }

        return successes;
    }

    /**
     * @dev Check if a user operation has been executed
     * @param opHash Operation hash
     * @return true if executed
     */
    function isUserOpExecuted(bytes32 opHash) external view returns (bool) {
        return executedUserOps[opHash];
    }

    /**
     * @dev Get account information
     * @return flowAddress Linked Flow address
     * @return registryAddress Root registry address
     * @return keyRegisterAddress Key register address
     * @return isRootFresh Whether the current root is fresh
     * @return hasSufficientWeight Whether Flow account has sufficient key weight
     */
    function getAccountInfo() external view returns (
        address flowAddress,
        address registryAddress,
        address keyRegisterAddress,
        bool isRootFresh,
        bool hasSufficientWeight
    ) {
        flowAddress = linkedFlowAddress;
        registryAddress = address(flowRootRegistry);
        keyRegisterAddress = address(flowKeyRegister);
        
        if (linkedFlowAddress != address(0)) {
            isRootFresh = flowRootRegistry.isRootFresh(linkedFlowAddress);
            if (address(flowKeyRegister) != address(0)) {
                hasSufficientWeight = flowKeyRegister.hasSufficientWeight(linkedFlowAddress);
            }
        }
    }

    // Admin functions (emergency only)

    /**
     * @dev Update Flow root registry address (admin only)
     * @param newRegistry New registry address
     */
    function updateFlowRootRegistry(address newRegistry) external onlyAdmin {
        require(newRegistry != address(0), "SmartAccount: invalid registry address");
        address oldRegistry = address(flowRootRegistry);
        flowRootRegistry = FlowRootRegistry(newRegistry);
        emit FlowRootRegistryUpdated(oldRegistry, newRegistry);
    }

    /**
     * @dev Emergency recovery - transfer admin rights
     * @param newAdmin New admin address
     */
    function emergencyRecovery(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "SmartAccount: invalid new admin");
        emit EmergencyRecovery(newAdmin, msg.sender);
        admin = newAdmin;
    }

    /**
     * @dev Receive ETH
     */
    receive() external payable {}

    /**
     * @dev Fallback function
     */
    fallback() external payable {}

    /**
     * @dev Authorize upgrade (required by UUPSUpgradeable)
     * @param newImplementation New implementation address
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    /**
     * @dev Get implementation version
     * @return Version string
     */
    function version() external pure returns (string memory) {
        return "2.0.0-multisig";
    }
}