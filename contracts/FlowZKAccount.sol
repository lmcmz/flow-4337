// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/core/BaseAccount.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./ZKVerifier.sol";

/**
 * @title FlowZKAccount
 * @dev ERC-4337 smart contract wallet controlled by Flow account via Zero-Knowledge Proofs
 * @notice This contract allows Flow blockchain accounts to control EVM operations
 *         through zero-knowledge proofs without revealing the Flow private key
 */
contract FlowZKAccount is BaseAccount, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    // Events
    event FlowAccountSet(uint256 indexed accountAddress, uint256 publicKeyX, uint256 publicKeyY);
    event ZKProofVerified(bytes32 indexed messageHash, uint256 nonce);
    event EmergencyRecoveryExecuted(address indexed newOwner);

    // State variables
    IEntryPoint private immutable _entryPoint;
    ZKVerifier private immutable _zkVerifier;
    
    // Flow account details
    uint256 public flowAccountAddress;
    uint256 public flowPublicKeyX;
    uint256 public flowPublicKeyY;
    
    // Nonce tracking for replay protection
    mapping(uint256 => bool) public usedNonces;
    
    // Emergency recovery
    address public emergencyRecoveryAddress;
    uint256 public constant RECOVERY_DELAY = 7 days;
    uint256 public recoveryInitiatedAt;

    // Errors
    error InvalidZKProof();
    error InvalidNonce();
    error NonceAlreadyUsed();
    error UnauthorizedCaller();
    error RecoveryNotInitiated();
    error RecoveryDelayNotMet();

    /**
     * @dev Constructor
     * @param anEntryPoint The ERC-4337 EntryPoint contract
     * @param zkVerifier The ZK proof verifier contract
     */
    constructor(IEntryPoint anEntryPoint, ZKVerifier zkVerifier) {
        _entryPoint = anEntryPoint;
        _zkVerifier = zkVerifier;
        _disableInitializers();
    }

    /**
     * @dev Initialize the account with Flow account details
     * @param _flowAccountAddress Flow account address
     * @param _flowPublicKeyX Flow account public key X coordinate
     * @param _flowPublicKeyY Flow account public key Y coordinate
     * @param _emergencyRecovery Emergency recovery address
     */
    function initialize(
        uint256 _flowAccountAddress,
        uint256 _flowPublicKeyX,
        uint256 _flowPublicKeyY,
        address _emergencyRecovery
    ) public initializer {
        flowAccountAddress = _flowAccountAddress;
        flowPublicKeyX = _flowPublicKeyX;
        flowPublicKeyY = _flowPublicKeyY;
        emergencyRecoveryAddress = _emergencyRecovery;
        
        emit FlowAccountSet(_flowAccountAddress, _flowPublicKeyX, _flowPublicKeyY);
    }

    /**
     * @dev Return the entryPoint used by this account
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @dev Validate UserOperation signature using ZK proof
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @return validationData Validation result (0 = valid, 1 = invalid)
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        // Extract ZK proof from signature
        (
            uint256[2] memory proof_a,
            uint256[2][2] memory proof_b,
            uint256[2] memory proof_c,
            uint256[] memory publicInputs
        ) = abi.decode(userOp.signature, (uint256[2], uint256[2][2], uint256[2], uint256[]));

        // Validate public inputs structure
        if (publicInputs.length != 5) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 messageHash = publicInputs[0];
        uint256 pubKeyX = publicInputs[1];
        uint256 pubKeyY = publicInputs[2];
        uint256 accountAddr = publicInputs[3];
        uint256 nonce = publicInputs[4];

        // Verify message hash matches userOpHash
        if (messageHash != uint256(userOpHash)) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify Flow account details match
        if (pubKeyX != flowPublicKeyX || 
            pubKeyY != flowPublicKeyY || 
            accountAddr != flowAccountAddress) {
            return SIG_VALIDATION_FAILED;
        }

        // Check nonce hasn't been used
        if (usedNonces[nonce]) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify ZK proof
        bool proofValid = _zkVerifier.verifyProof(
            proof_a,
            proof_b,
            proof_c,
            publicInputs
        );

        if (!proofValid) {
            return SIG_VALIDATION_FAILED;
        }

        // Mark nonce as used
        usedNonces[nonce] = true;
        
        emit ZKProofVerified(userOpHash, nonce);
        return 0; // Valid signature
    }

    /**
     * @dev Update Flow account details (only callable by this account)
     * @param _flowAccountAddress New Flow account address
     * @param _flowPublicKeyX New Flow account public key X coordinate
     * @param _flowPublicKeyY New Flow account public key Y coordinate
     */
    function updateFlowAccount(
        uint256 _flowAccountAddress,
        uint256 _flowPublicKeyX,
        uint256 _flowPublicKeyY
    ) external {
        _requireFromEntryPointOrOwner();
        
        flowAccountAddress = _flowAccountAddress;
        flowPublicKeyX = _flowPublicKeyX;
        flowPublicKeyY = _flowPublicKeyY;
        
        emit FlowAccountSet(_flowAccountAddress, _flowPublicKeyX, _flowPublicKeyY);
    }

    /**
     * @dev Initiate emergency recovery process
     */
    function initiateRecovery() external {
        if (msg.sender != emergencyRecoveryAddress) {
            revert UnauthorizedCaller();
        }
        
        recoveryInitiatedAt = block.timestamp;
    }

    /**
     * @dev Execute emergency recovery after delay
     * @param newFlowAccountAddress New Flow account address
     * @param newFlowPublicKeyX New Flow account public key X coordinate
     * @param newFlowPublicKeyY New Flow account public key Y coordinate
     */
    function executeRecovery(
        uint256 newFlowAccountAddress,
        uint256 newFlowPublicKeyX,
        uint256 newFlowPublicKeyY
    ) external {
        if (msg.sender != emergencyRecoveryAddress) {
            revert UnauthorizedCaller();
        }
        
        if (recoveryInitiatedAt == 0) {
            revert RecoveryNotInitiated();
        }
        
        if (block.timestamp < recoveryInitiatedAt + RECOVERY_DELAY) {
            revert RecoveryDelayNotMet();
        }

        flowAccountAddress = newFlowAccountAddress;
        flowPublicKeyX = newFlowPublicKeyX;
        flowPublicKeyY = newFlowPublicKeyY;
        
        // Reset recovery state
        recoveryInitiatedAt = 0;
        
        emit EmergencyRecoveryExecuted(msg.sender);
        emit FlowAccountSet(newFlowAccountAddress, newFlowPublicKeyX, newFlowPublicKeyY);
    }

    /**
     * @dev Check if nonce has been used
     * @param nonce Nonce to check
     * @return bool True if nonce has been used
     */
    function isNonceUsed(uint256 nonce) external view returns (bool) {
        return usedNonces[nonce];
    }

    /**
     * @dev Get Flow account details
     * @return accountAddress Flow account address
     * @return publicKeyX Public key X coordinate
     * @return publicKeyY Public key Y coordinate
     */
    function getFlowAccount() external view returns (
        uint256 accountAddress,
        uint256 publicKeyX,
        uint256 publicKeyY
    ) {
        return (flowAccountAddress, flowPublicKeyX, flowPublicKeyY);
    }

    /**
     * @dev Internal function to authorize upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal override {
        _requireFromEntryPointOrOwner();
    }

    /**
     * @dev Internal function to check authorization
     */
    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != address(this)) {
            revert UnauthorizedCaller();
        }
    }

    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {}
}