// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./interfaces/IEntryPoint.sol";
import "./FlowRootRegistry.sol";

/**
 * @title FlowControlledSmartAccount
 * @dev ERC-4337 Smart Account controlled by Flow keys via Merkle proof verification
 * @notice Verifies Flow key ownership through Merkle proofs without exposing individual keys
 */
contract FlowControlledSmartAccount is Initializable, UUPSUpgradeable, Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    // Events
    event FlowAccountLinked(address indexed flowAddress, address indexed smartAccount);
    event UserOperationExecuted(bytes32 indexed userOpHash, address indexed flowAddress, bool success);
    event FlowRootRegistryUpdated(address indexed oldRegistry, address indexed newRegistry);
    event EmergencyRecovery(address indexed newOwner, address indexed initiator);

    // Flow key validation data structure
    struct FlowControlledUserOp {
        address flowAddress;          // Flow account address
        bytes32 opHash;              // keccak256(UserOperation)
        bytes publicKey;             // Uncompressed public key (64 bytes, no 04 prefix)
        uint256 weight;              // Key weight from Flow account
        uint8 hashAlgorithm;         // Hash algorithm ID
        uint8 signatureAlgorithm;    // Signature algorithm ID
        bytes signature;             // secp256k1 or p256 signature
        bytes32[] merkleProof;       // Merkle proof for key inclusion
    }

    // State variables
    FlowRootRegistry public flowRootRegistry;
    address public linkedFlowAddress;
    mapping(bytes32 => bool) public executedUserOps;
    
    // Constants
    uint8 public constant ECDSA_P256 = 1;
    uint8 public constant ECDSA_SECP256K1 = 2;
    uint8 public constant SHA2_256 = 1;
    uint8 public constant SHA3_256 = 2;
    
    // Minimum key weight required for operations
    uint256 public constant MIN_KEY_WEIGHT = 100; // 0.01 in Flow's weight system (1000 = 1.0)

    modifier onlyLinkedFlow() {
        require(linkedFlowAddress != address(0), "SmartAccount: no Flow account linked");
        _;
    }

    modifier validSignatureAlgorithm(uint8 algorithm) {
        require(
            algorithm == ECDSA_P256 || algorithm == ECDSA_SECP256K1,
            "SmartAccount: unsupported signature algorithm"
        );
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initialize the smart account
     * @param _flowRootRegistry Address of the Flow root registry
     * @param _flowAddress Flow account address to link
     * @param _owner Initial owner address
     */
    function initialize(
        address _flowRootRegistry,
        address _flowAddress,
        address _owner
    ) public initializer {
        require(_flowRootRegistry != address(0), "SmartAccount: invalid registry address");
        require(_flowAddress != address(0), "SmartAccount: invalid Flow address");
        require(_owner != address(0), "SmartAccount: invalid owner address");

        __UUPSUpgradeable_init();
        __Ownable_init();
        _transferOwnership(_owner);

        flowRootRegistry = FlowRootRegistry(_flowRootRegistry);
        linkedFlowAddress = _flowAddress;

        emit FlowAccountLinked(_flowAddress, address(this));
    }

    /**
     * @dev Validate user operation with Flow key proof
     * @param userOp Flow-controlled user operation data
     * @return validationData Validation result (0 = success, 1 = failure)
     */
    function validateUserOp(
        FlowControlledUserOp memory userOp
    ) public view returns (uint256 validationData) {
        try this._validateUserOpInternal(userOp) returns (bool isValid) {
            return isValid ? 0 : 1;
        } catch {
            return 1;
        }
    }

    /**
     * @dev Internal validation logic (public for try-catch)
     * @param userOp Flow-controlled user operation data
     * @return true if validation passes
     */
    function _validateUserOpInternal(
        FlowControlledUserOp memory userOp
    ) public view returns (bool) {
        // 1. Verify Flow address matches linked account
        require(userOp.flowAddress == linkedFlowAddress, "SmartAccount: Flow address mismatch");

        // 2. Verify operation hasn't been executed
        require(!executedUserOps[userOp.opHash], "SmartAccount: operation already executed");

        // 3. Verify key weight meets minimum requirement
        require(userOp.weight >= MIN_KEY_WEIGHT, "SmartAccount: insufficient key weight");

        // 4. Verify signature algorithm is supported
        require(
            userOp.signatureAlgorithm == ECDSA_P256 || userOp.signatureAlgorithm == ECDSA_SECP256K1,
            "SmartAccount: unsupported signature algorithm"
        );

        // 5. Verify public key format
        require(userOp.publicKey.length == 64, "SmartAccount: invalid public key length");

        // 6. Get current Merkle root from registry
        bytes32 storedRoot = flowRootRegistry.getRoot(userOp.flowAddress);
        require(storedRoot != bytes32(0), "SmartAccount: no root found for Flow address");

        // 7. Verify root is fresh
        require(flowRootRegistry.isRootFresh(userOp.flowAddress), "SmartAccount: stale root");

        // 8. Create leaf hash from key data
        bytes32 leaf = flowRootRegistry.createLeafHash(
            userOp.publicKey,
            userOp.weight,
            userOp.hashAlgorithm,
            userOp.signatureAlgorithm
        );

        // 9. Verify Merkle proof
        require(
            flowRootRegistry.verifyMerkleProof(leaf, userOp.merkleProof, storedRoot),
            "SmartAccount: invalid Merkle proof"
        );

        // 10. Verify signature
        address expectedSigner = flowRootRegistry.pubkeyToAddress(
            userOp.publicKey,
            userOp.signatureAlgorithm
        );

        address recoveredSigner;
        if (userOp.signatureAlgorithm == ECDSA_SECP256K1) {
            recoveredSigner = userOp.opHash.recover(userOp.signature);
        } else {
            // For P256, we need specialized verification
            recoveredSigner = _verifyP256Signature(userOp.opHash, userOp.signature, userOp.publicKey);
        }

        require(recoveredSigner == expectedSigner, "SmartAccount: invalid signature");

        return true;
    }

    /**
     * @dev Execute a validated user operation
     * @param userOp Flow-controlled user operation data
     * @param target Target contract address
     * @param data Call data
     * @param value ETH value to send
     * @return success Execution result
     */
    function executeUserOp(
        FlowControlledUserOp memory userOp,
        address target,
        bytes calldata data,
        uint256 value
    ) external nonReentrant onlyLinkedFlow returns (bool success) {
        // Validate the user operation
        require(validateUserOp(userOp) == 0, "SmartAccount: validation failed");

        // Mark operation as executed
        executedUserOps[userOp.opHash] = true;

        // Execute the operation
        (success, ) = target.call{value: value}(data);

        emit UserOperationExecuted(userOp.opHash, userOp.flowAddress, success);
        return success;
    }

    /**
     * @dev Batch execute multiple operations
     * @param userOps Array of user operations
     * @param targets Array of target addresses
     * @param datas Array of call data
     * @param values Array of ETH values
     * @return successes Array of execution results
     */
    function batchExecuteUserOps(
        FlowControlledUserOp[] memory userOps,
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
            
            // Execute
            (successes[i], ) = targets[i].call{value: values[i]}(datas[i]);
            
            emit UserOperationExecuted(userOps[i].opHash, userOps[i].flowAddress, successes[i]);
        }

        return successes;
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
        // In production, you'd use a proper P256 signature verification library
        // For now, we'll derive an address from the public key for P256
        return address(uint160(uint256(keccak256(abi.encodePacked("P256:", publicKey, hash)))));
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
     * @return isRootFresh Whether the current root is fresh
     */
    function getAccountInfo() external view returns (
        address flowAddress,
        address registryAddress,
        bool isRootFresh
    ) {
        flowAddress = linkedFlowAddress;
        registryAddress = address(flowRootRegistry);
        isRootFresh = linkedFlowAddress != address(0) ? 
            flowRootRegistry.isRootFresh(linkedFlowAddress) : false;
    }

    // Admin functions

    /**
     * @dev Update Flow root registry address
     * @param newRegistry New registry address
     */
    function updateFlowRootRegistry(address newRegistry) external onlyOwner {
        require(newRegistry != address(0), "SmartAccount: invalid registry address");
        address oldRegistry = address(flowRootRegistry);
        flowRootRegistry = FlowRootRegistry(newRegistry);
        emit FlowRootRegistryUpdated(oldRegistry, newRegistry);
    }

    /**
     * @dev Emergency recovery - transfer ownership
     * @param newOwner New owner address
     */
    function emergencyRecovery(address newOwner) external onlyOwner {
        require(newOwner != address(0), "SmartAccount: invalid new owner");
        emit EmergencyRecovery(newOwner, msg.sender);
        _transferOwnership(newOwner);
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
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Get implementation version
     * @return Version string
     */
    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}