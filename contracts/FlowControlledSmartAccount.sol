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
 * @title FlowControlledSmartAccount
 * @dev ERC-4337 Smart Account with multi-signature Flow key validation
 * @notice Supports multiple Flow keys with weight-based threshold validation (sum >= 1000)
 */
contract FlowControlledSmartAccount is Initializable, UUPSUpgradeable, ReentrancyGuard {
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

        // Verify signature directly against original message and public key
        if (keyInfo.signatureAlgorithm == ECDSA_SECP256K1) {
            // For secp256k1, verify signature against public key by comparing addresses
            return _verifySecp256k1SignatureAgainstKey(opHash, signature, keyInfo.publicKey);
        } else {
            // For P256, use direct signature verification against public key
            return _verifyP256SignatureAgainstKey(opHash, signature, keyInfo.publicKey);
        }
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
     * @dev Verify secp256k1 signature directly against public key
     * @param hash Message hash
     * @param signature Signature bytes
     * @param publicKey Public key bytes (uncompressed, 64 bytes)
     * @return isValid True if signature is valid
     */
    function _verifySecp256k1SignatureAgainstKey(
        bytes32 hash,
        bytes memory signature,
        bytes memory publicKey
    ) internal pure returns (bool isValid) {
        // Validate input lengths
        require(signature.length == 65, "SmartAccount: invalid secp256k1 signature length");
        require(publicKey.length == 64, "SmartAccount: invalid secp256k1 public key length");
        
        // Derive expected address from public key
        // Ethereum address = last 20 bytes of keccak256(publicKey)
        bytes32 publicKeyHash = keccak256(publicKey);
        address expectedSigner = address(uint160(uint256(publicKeyHash)));
        
        // Recover signer address from signature using ecrecover
        address recoveredSigner = hash.recover(signature);
        
        // Compare addresses - if they match, signature is valid for this public key
        return (recoveredSigner == expectedSigner);
    }

    /**
     * @dev Verify P256 signature directly against public key using multiple verification methods
     * @param hash Message hash
     * @param signature Signature bytes (r,s components)
     * @param publicKey Public key bytes (uncompressed, 64 bytes)
     * @return isValid True if signature is valid
     * 
     * This function tries multiple P256 verification methods in order of efficiency:
     * 1. EIP-7212 precompile (3,450 gas) - most efficient
     * 2. daimo-eth p256-verifier (~330k gas) - audited and secure
     * 3. Custom P256 verification using curve arithmetic libraries
     */
    function _verifyP256SignatureAgainstKey(
        bytes32 hash,
        bytes memory signature,
        bytes memory publicKey
    ) internal view returns (bool isValid) {
        // Validate input lengths
        require(signature.length == 64, "SmartAccount: invalid P256 signature length");
        require(publicKey.length == 64, "SmartAccount: invalid P256 public key length");
        
        // Method 1: Try EIP-7212 P256 precompile (most efficient if available)
        // Input format: hash(32) + r(32) + s(32) + x(32) + y(32)
        bytes memory precompileInput = abi.encodePacked(hash, signature, publicKey);
        
        (bool precompileSuccess, bytes memory precompileResult) = address(0x100).staticcall(precompileInput);
        
        if (precompileSuccess && precompileResult.length == 32) {
            // If precompile is available and working, use its result
            return abi.decode(precompileResult, (bool));
        }
        
        // Method 2: Try daimo-eth p256-verifier (audited, production-ready)
        // Available at deterministic CREATE2 address on most networks
        address daimoVerifier = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
        
        // Check if the daimo verifier contract exists
        uint256 daimoCodeSize;
        assembly {
            daimoCodeSize := extcodesize(daimoVerifier)
        }
        
        if (daimoCodeSize > 0) {
            // Extract signature and public key components
            bytes32 r;
            bytes32 s;
            bytes32 x;
            bytes32 y;
            
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                x := mload(add(publicKey, 0x20))
                y := mload(add(publicKey, 0x40))
            }
            
            // Call daimo-eth p256-verifier
            bytes memory daimoCall = abi.encodeWithSignature(
                "verifySignatureAllowMalleability(bytes32,uint256,uint256,uint256,uint256)",
                hash,
                uint256(r),
                uint256(s),
                uint256(x),
                uint256(y)
            );
            
            (bool daimoSuccess, bytes memory daimoResult) = daimoVerifier.staticcall(daimoCall);
            
            if (daimoSuccess && daimoResult.length == 32) {
                return abi.decode(daimoResult, (bool));
            }
        }
        
        // Method 3: Try custom P256 verification using witnet/elliptic-curve-solidity
        // This would require importing the EllipticCurve library and implementing
        // ECDSA verification logic using curve arithmetic operations
        // For now, we skip this as it would require additional dependencies
        
        // All verification methods failed or are unavailable
        revert("SmartAccount: P256 verification unavailable - requires EIP-7212 precompile, daimo p256-verifier, or custom implementation");
    }
    
    /**
     * @dev Legacy P256 signature verification (deprecated)
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
        // Note: This is a deprecated implementation that uses address comparison
        // Use _verifyP256SignatureAgainstKey for proper signature verification
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
        return "1.0.0-multisig";
    }
}