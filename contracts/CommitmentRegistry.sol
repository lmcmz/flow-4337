// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title CommitmentRegistry
 * @dev Registry for authorized Flow account commitments
 * @notice Manages which commitments are authorized to control ERC-4337 accounts
 *         Provides privacy by not revealing the actual Flow accounts
 */
contract CommitmentRegistry is Ownable, Pausable {
    
    // Events
    event CommitmentAuthorized(bytes32 indexed commitment, address indexed authorizer);
    event CommitmentRevoked(bytes32 indexed commitment, address indexed revoker);
    event CommitmentRegistered(bytes32 indexed commitment, address indexed account);
    event AuthorizerAdded(address indexed authorizer);
    event AuthorizerRemoved(address indexed authorizer);

    // State variables
    mapping(bytes32 => bool) public authorizedCommitments;
    mapping(bytes32 => address) public commitmentToAccount;  // Maps commitment to ERC-4337 account
    mapping(address => bytes32) public accountToCommitment;  // Maps ERC-4337 account to commitment
    mapping(address => bool) public authorizers;            // Addresses that can authorize commitments
    
    // Commitment metadata
    mapping(bytes32 => CommitmentInfo) public commitmentInfo;
    
    struct CommitmentInfo {
        uint256 authorizedAt;
        address authorizedBy;
        bool isActive;
        uint256 expiresAt;  // 0 means no expiry
    }

    // Errors
    error CommitmentAlreadyAuthorized();
    error CommitmentNotAuthorized();
    error NotAuthorizer();
    error InvalidCommitment();
    error CommitmentExpired();
    error AccountAlreadyRegistered();

    modifier onlyAuthorizer() {
        if (!authorizers[msg.sender] && msg.sender != owner()) {
            revert NotAuthorizer();
        }
        _;
    }

    constructor() {
        // Owner is initial authorizer
        authorizers[msg.sender] = true;
        emit AuthorizerAdded(msg.sender);
    }

    /**
     * @dev Authorize a Flow account commitment
     * @param commitment Hash commitment to Flow account
     * @param expiresAt Expiry timestamp (0 for no expiry)
     */
    function authorizeCommitment(
        bytes32 commitment,
        uint256 expiresAt
    ) external onlyAuthorizer whenNotPaused {
        if (commitment == bytes32(0)) {
            revert InvalidCommitment();
        }
        
        if (authorizedCommitments[commitment]) {
            revert CommitmentAlreadyAuthorized();
        }

        authorizedCommitments[commitment] = true;
        commitmentInfo[commitment] = CommitmentInfo({
            authorizedAt: block.timestamp,
            authorizedBy: msg.sender,
            isActive: true,
            expiresAt: expiresAt
        });

        emit CommitmentAuthorized(commitment, msg.sender);
    }

    /**
     * @dev Revoke an authorized commitment
     * @param commitment Commitment to revoke
     */
    function revokeCommitment(bytes32 commitment) external onlyAuthorizer {
        if (!authorizedCommitments[commitment]) {
            revert CommitmentNotAuthorized();
        }

        authorizedCommitments[commitment] = false;
        commitmentInfo[commitment].isActive = false;

        emit CommitmentRevoked(commitment, msg.sender);
    }

    /**
     * @dev Register commitment with ERC-4337 account
     * @param commitment Account commitment
     * @param account ERC-4337 account address
     */
    function registerCommitmentWithAccount(
        bytes32 commitment,
        address account
    ) external onlyAuthorizer {
        if (!isCommitmentAuthorized(commitment)) {
            revert CommitmentNotAuthorized();
        }

        if (accountToCommitment[account] != bytes32(0)) {
            revert AccountAlreadyRegistered();
        }

        commitmentToAccount[commitment] = account;
        accountToCommitment[account] = commitment;

        emit CommitmentRegistered(commitment, account);
    }

    /**
     * @dev Check if commitment is authorized and not expired
     * @param commitment Commitment to check
     * @return True if commitment is authorized and valid
     */
    function isCommitmentAuthorized(bytes32 commitment) public view returns (bool) {
        if (!authorizedCommitments[commitment]) {
            return false;
        }

        CommitmentInfo memory info = commitmentInfo[commitment];
        
        if (!info.isActive) {
            return false;
        }

        // Check expiry (0 means no expiry)
        if (info.expiresAt != 0 && block.timestamp > info.expiresAt) {
            return false;
        }

        return true;
    }

    /**
     * @dev Get commitment info
     * @param commitment Commitment to query
     * @return info Commitment information
     */
    function getCommitmentInfo(bytes32 commitment) external view returns (CommitmentInfo memory info) {
        return commitmentInfo[commitment];
    }

    /**
     * @dev Get account for commitment
     * @param commitment Commitment to query
     * @return account ERC-4337 account address
     */
    function getAccountForCommitment(bytes32 commitment) external view returns (address account) {
        return commitmentToAccount[commitment];
    }

    /**
     * @dev Get commitment for account
     * @param account ERC-4337 account address
     * @return commitment Account commitment
     */
    function getCommitmentForAccount(address account) external view returns (bytes32 commitment) {
        return accountToCommitment[account];
    }

    /**
     * @dev Add authorizer
     * @param authorizer Address to add as authorizer
     */
    function addAuthorizer(address authorizer) external onlyOwner {
        authorizers[authorizer] = true;
        emit AuthorizerAdded(authorizer);
    }

    /**
     * @dev Remove authorizer
     * @param authorizer Address to remove from authorizers
     */
    function removeAuthorizer(address authorizer) external onlyOwner {
        authorizers[authorizer] = false;
        emit AuthorizerRemoved(authorizer);
    }

    /**
     * @dev Batch authorize commitments
     * @param commitments Array of commitments to authorize
     * @param expiresAt Expiry timestamp for all commitments
     */
    function batchAuthorizeCommitments(
        bytes32[] calldata commitments,
        uint256 expiresAt
    ) external onlyAuthorizer whenNotPaused {
        for (uint256 i = 0; i < commitments.length; i++) {
            bytes32 commitment = commitments[i];
            
            if (commitment == bytes32(0)) {
                continue; // Skip invalid commitments
            }
            
            if (authorizedCommitments[commitment]) {
                continue; // Skip already authorized
            }

            authorizedCommitments[commitment] = true;
            commitmentInfo[commitment] = CommitmentInfo({
                authorizedAt: block.timestamp,
                authorizedBy: msg.sender,
                isActive: true,
                expiresAt: expiresAt
            });

            emit CommitmentAuthorized(commitment, msg.sender);
        }
    }

    /**
     * @dev Get total authorized commitments count
     * @return count Number of authorized commitments
     * @dev Note: This is a gas-intensive operation for large registries
     */
    function getAuthorizedCommitmentsCount() external view returns (uint256 count) {
        // This would require additional state tracking for efficient implementation
        // For now, this is a placeholder that would need optimization
        return 0; // TODO: Implement efficient counting
    }

    /**
     * @dev Check if address is authorizer
     * @param addr Address to check
     * @return True if address is authorizer
     */
    function isAuthorizer(address addr) external view returns (bool) {
        return authorizers[addr] || addr == owner();
    }

    /**
     * @dev Pause the contract
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause the contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Emergency function to update commitment expiry
     * @param commitment Commitment to update
     * @param newExpiresAt New expiry timestamp
     */
    function updateCommitmentExpiry(
        bytes32 commitment,
        uint256 newExpiresAt
    ) external onlyOwner {
        if (!authorizedCommitments[commitment]) {
            revert CommitmentNotAuthorized();
        }

        commitmentInfo[commitment].expiresAt = newExpiresAt;
    }
}