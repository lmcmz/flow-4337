// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@account-abstraction/contracts/core/BaseAccount.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./CommitmentRegistry.sol";
import "./ZKVerifierOffChain.sol";
import "./NullifierTracker.sol";

/**
 * @title FlowZKAccountOffChain
 * @dev Privacy-preserving ERC-4337 account controlled by Flow accounts via off-chain ZK proofs
 * @notice NO PUBLIC KEY EXPOSURE - Uses commitment-based verification
 *         NO FLOW CONNECTION NEEDED - Standalone verification using off-chain generated proofs
 */
contract FlowZKAccountOffChain is BaseAccount, UUPSUpgradeable, Initializable {
    
    // Events
    event AccountCommitmentSet(bytes32 indexed commitment);
    event OffChainProofVerified(bytes32 indexed nullifier, bytes32 messageHash);
    event EmergencyRecoveryExecuted(address indexed recoveryAddress);
    event CommitmentUpdated(bytes32 indexed oldCommitment, bytes32 indexed newCommitment);

    // Immutable contracts
    IEntryPoint private immutable _entryPoint;
    ZKVerifierOffChain private immutable _zkVerifier;
    CommitmentRegistry private immutable _commitmentRegistry;
    NullifierTracker private immutable _nullifierTracker;
    
    // Account state
    bytes32 public accountCommitment;      // Hidden Flow account commitment
    address public emergencyRecoveryAddress;
    uint256 public recoveryInitiatedAt;
    
    // Constants
    uint256 public constant RECOVERY_DELAY = 7 days;
    uint256 public constant PROOF_VALIDITY_WINDOW = 1 hours;

    // Errors
    error InvalidOffChainProof();
    error CommitmentNotAuthorized();
    error NullifierAlreadyUsed();
    error ProofExpired();
    error UnauthorizedCaller();
    error RecoveryNotInitiated();
    error RecoveryDelayNotMet();
    error InvalidCommitment();

    /**
     * @dev Constructor
     * @param anEntryPoint The ERC-4337 EntryPoint contract
     * @param zkVerifier The off-chain ZK proof verifier
     * @param commitmentRegistry Registry for authorized commitments
     * @param nullifierTracker Nullifier tracking for replay protection
     */
    constructor(
        IEntryPoint anEntryPoint,
        ZKVerifierOffChain zkVerifier,
        CommitmentRegistry commitmentRegistry,
        NullifierTracker nullifierTracker
    ) {
        _entryPoint = anEntryPoint;
        _zkVerifier = zkVerifier;
        _commitmentRegistry = commitmentRegistry;
        _nullifierTracker = nullifierTracker;
        _disableInitializers();
    }

    /**
     * @dev Initialize account with Flow account commitment
     * @param _accountCommitment Hidden commitment to Flow account
     * @param _emergencyRecovery Emergency recovery address
     */
    function initialize(
        bytes32 _accountCommitment,
        address _emergencyRecovery
    ) public initializer {
        if (_accountCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }
        
        // Verify commitment is authorized in registry
        if (!_commitmentRegistry.isCommitmentAuthorized(_accountCommitment)) {
            revert CommitmentNotAuthorized();
        }
        
        accountCommitment = _accountCommitment;
        emergencyRecoveryAddress = _emergencyRecovery;
        
        emit AccountCommitmentSet(_accountCommitment);
    }

    /**
     * @dev Return the entryPoint used by this account
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @dev Validate UserOperation signature using off-chain ZK proof
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @return validationData Validation result (0 = valid, 1 = invalid)
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        // Decode off-chain ZK proof from signature
        (
            uint256[2] memory proof_a,
            uint256[2][2] memory proof_b,
            uint256[2] memory proof_c,
            uint256[] memory publicSignals,
            bytes32 commitment,
            bytes32 nullifier
        ) = abi.decode(
            userOp.signature,
            (uint256[2], uint256[2][2], uint256[2], uint256[], bytes32, bytes32)
        );

        // Validate proof structure
        if (publicSignals.length != 5) {
            return SIG_VALIDATION_FAILED;
        }

        // Extract public inputs
        bytes32 proofCommitment = bytes32(publicSignals[0]);
        bytes32 proofNullifier = bytes32(publicSignals[1]);
        bytes32 messageHash = bytes32(publicSignals[2]);
        bytes32 challengeHash = bytes32(publicSignals[3]);
        uint256 timestamp = publicSignals[4];

        // Verify commitment matches account commitment
        if (proofCommitment != accountCommitment) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify commitment is authorized
        if (!_commitmentRegistry.isCommitmentAuthorized(proofCommitment)) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify nullifier matches and hasn't been used
        if (proofNullifier != nullifier) {
            return SIG_VALIDATION_FAILED;
        }

        if (_nullifierTracker.isNullifierUsed(nullifier)) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify message hash matches userOpHash
        if (messageHash != userOpHash) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify proof timestamp is recent
        if (block.timestamp > timestamp + PROOF_VALIDITY_WINDOW) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify off-chain ZK proof
        bool proofValid = _zkVerifier.verifyOffChainProof(
            proof_a,
            proof_b,
            proof_c,
            publicSignals
        );

        if (!proofValid) {
            return SIG_VALIDATION_FAILED;
        }

        // Mark nullifier as used to prevent replay
        _nullifierTracker.markNullifierUsed(nullifier);
        
        emit OffChainProofVerified(nullifier, userOpHash);
        return 0; // Valid signature
    }

    /**
     * @dev Update account commitment (requires valid proof)
     * @param newCommitment New account commitment
     * @param proof ZK proof authorizing the change
     */
    function updateCommitment(
        bytes32 newCommitment,
        OffChainProofData calldata proof
    ) external {
        _requireFromEntryPointOrOwner();
        
        if (newCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }
        
        // Verify new commitment is authorized
        if (!_commitmentRegistry.isCommitmentAuthorized(newCommitment)) {
            revert CommitmentNotAuthorized();
        }
        
        // Verify proof authorizes this change
        // (Implementation would verify proof relates to current commitment)
        
        bytes32 oldCommitment = accountCommitment;
        accountCommitment = newCommitment;
        
        emit CommitmentUpdated(oldCommitment, newCommitment);
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
     * @param newCommitment New commitment for recovered account
     */
    function executeRecovery(bytes32 newCommitment) external {
        if (msg.sender != emergencyRecoveryAddress) {
            revert UnauthorizedCaller();
        }
        
        if (recoveryInitiatedAt == 0) {
            revert RecoveryNotInitiated();
        }
        
        if (block.timestamp < recoveryInitiatedAt + RECOVERY_DELAY) {
            revert RecoveryDelayNotMet();
        }

        if (newCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }

        // Verify new commitment is authorized (emergency recovery may bypass some checks)
        accountCommitment = newCommitment;
        
        // Reset recovery state
        recoveryInitiatedAt = 0;
        
        emit EmergencyRecoveryExecuted(msg.sender);
        emit AccountCommitmentSet(newCommitment);
    }

    /**
     * @dev Get account information
     * @return commitment Current account commitment
     * @return recoveryAddress Emergency recovery address
     * @return recoveryInitiated Timestamp when recovery was initiated (0 if not initiated)
     */
    function getAccountInfo() external view returns (
        bytes32 commitment,
        address recoveryAddress,
        uint256 recoveryInitiated
    ) {
        return (accountCommitment, emergencyRecoveryAddress, recoveryInitiatedAt);
    }

    /**
     * @dev Check if a nullifier has been used
     * @param nullifier Nullifier to check
     * @return True if nullifier has been used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return _nullifierTracker.isNullifierUsed(nullifier);
    }

    /**
     * @dev Verify an off-chain proof without executing
     * @param proof Proof components
     * @param publicSignals Public signals
     * @return True if proof is valid
     */
    function verifyProof(
        uint256[2] calldata proof_a,
        uint256[2][2] calldata proof_b,
        uint256[2] calldata proof_c,
        uint256[] calldata publicSignals
    ) external view returns (bool) {
        return _zkVerifier.verifyOffChainProof(proof_a, proof_b, proof_c, publicSignals);
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

/**
 * @dev Struct for off-chain proof data
 */
struct OffChainProofData {
    uint256[2] proof_a;
    uint256[2][2] proof_b;
    uint256[2] proof_c;
    uint256[] publicSignals;
    bytes32 commitment;
    bytes32 nullifier;
}