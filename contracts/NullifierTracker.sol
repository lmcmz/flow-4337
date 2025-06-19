// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title NullifierTracker
 * @dev Tracks used nullifiers to prevent replay attacks in off-chain ZK proofs
 * @notice Maintains a registry of used nullifiers for privacy-preserving proof verification
 */
contract NullifierTracker is Ownable, Pausable {
    
    // Events
    event NullifierUsed(bytes32 indexed nullifier, address indexed account);
    event NullifierBatchProcessed(uint256 count);
    event TrackerCleared(address indexed clearer);
    event AuthorizedCallerAdded(address indexed caller);
    event AuthorizedCallerRemoved(address indexed caller);

    // State variables
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => NullifierInfo) public nullifierInfo;
    mapping(address => bool) public authorizedCallers;  // Contracts that can mark nullifiers as used
    
    struct NullifierInfo {
        uint256 usedAt;
        address usedBy;
        address account;  // ERC-4337 account that used this nullifier
    }

    // Statistics
    uint256 public totalNullifiersUsed;
    
    // Errors
    error NullifierAlreadyUsed();
    error NotAuthorizedCaller();
    error InvalidNullifier();
    error NullifierNotUsed();

    modifier onlyAuthorizedCaller() {
        if (!authorizedCallers[msg.sender] && msg.sender != owner()) {
            revert NotAuthorizedCaller();
        }
        _;
    }

    constructor() {
        // Owner is initially authorized
        authorizedCallers[msg.sender] = true;
        emit AuthorizedCallerAdded(msg.sender);
    }

    /**
     * @dev Mark a nullifier as used
     * @param nullifier Nullifier to mark as used
     * @param account ERC-4337 account using this nullifier
     */
    function markNullifierUsed(
        bytes32 nullifier,
        address account
    ) external onlyAuthorizedCaller whenNotPaused {
        if (nullifier == bytes32(0)) {
            revert InvalidNullifier();
        }
        
        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        usedNullifiers[nullifier] = true;
        nullifierInfo[nullifier] = NullifierInfo({
            usedAt: block.timestamp,
            usedBy: msg.sender,
            account: account
        });

        totalNullifiersUsed++;

        emit NullifierUsed(nullifier, account);
    }

    /**
     * @dev Mark a nullifier as used (simple version for authorized callers)
     * @param nullifier Nullifier to mark as used
     */
    function markNullifierUsed(bytes32 nullifier) external onlyAuthorizedCaller whenNotPaused {
        markNullifierUsed(nullifier, address(0));
    }

    /**
     * @dev Check if a nullifier has been used
     * @param nullifier Nullifier to check
     * @return True if nullifier has been used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /**
     * @dev Get nullifier information
     * @param nullifier Nullifier to query
     * @return info Nullifier information
     */
    function getNullifierInfo(bytes32 nullifier) external view returns (NullifierInfo memory info) {
        return nullifierInfo[nullifier];
    }

    /**
     * @dev Batch mark nullifiers as used
     * @param nullifiers Array of nullifiers to mark as used
     * @param account ERC-4337 account using these nullifiers
     */
    function batchMarkNullifiersUsed(
        bytes32[] calldata nullifiers,
        address account
    ) external onlyAuthorizedCaller whenNotPaused {
        uint256 count = 0;
        
        for (uint256 i = 0; i < nullifiers.length; i++) {
            bytes32 nullifier = nullifiers[i];
            
            if (nullifier == bytes32(0) || usedNullifiers[nullifier]) {
                continue; // Skip invalid or already used nullifiers
            }

            usedNullifiers[nullifier] = true;
            nullifierInfo[nullifier] = NullifierInfo({
                usedAt: block.timestamp,
                usedBy: msg.sender,
                account: account
            });

            count++;
            emit NullifierUsed(nullifier, account);
        }

        totalNullifiersUsed += count;
        emit NullifierBatchProcessed(count);
    }

    /**
     * @dev Check multiple nullifiers at once
     * @param nullifiers Array of nullifiers to check
     * @return used Array of booleans indicating if each nullifier is used
     */
    function areNullifiersUsed(bytes32[] calldata nullifiers) external view returns (bool[] memory used) {
        used = new bool[](nullifiers.length);
        for (uint256 i = 0; i < nullifiers.length; i++) {
            used[i] = usedNullifiers[nullifiers[i]];
        }
        return used;
    }

    /**
     * @dev Add authorized caller
     * @param caller Address to authorize
     */
    function addAuthorizedCaller(address caller) external onlyOwner {
        authorizedCallers[caller] = true;
        emit AuthorizedCallerAdded(caller);
    }

    /**
     * @dev Remove authorized caller
     * @param caller Address to remove authorization
     */
    function removeAuthorizedCaller(address caller) external onlyOwner {
        authorizedCallers[caller] = false;
        emit AuthorizedCallerRemoved(caller);
    }

    /**
     * @dev Check if address is authorized caller
     * @param caller Address to check
     * @return True if caller is authorized
     */
    function isAuthorizedCaller(address caller) external view returns (bool) {
        return authorizedCallers[caller] || caller == owner();
    }

    /**
     * @dev Get nullifiers used by a specific account
     * @param account ERC-4337 account address
     * @param nullifiers Array of nullifiers to check
     * @return accountNullifiers Array of nullifiers used by the account
     */
    function getNullifiersUsedByAccount(
        address account,
        bytes32[] calldata nullifiers
    ) external view returns (bytes32[] memory accountNullifiers) {
        bytes32[] memory temp = new bytes32[](nullifiers.length);
        uint256 count = 0;
        
        for (uint256 i = 0; i < nullifiers.length; i++) {
            if (usedNullifiers[nullifiers[i]] && nullifierInfo[nullifiers[i]].account == account) {
                temp[count] = nullifiers[i];
                count++;
            }
        }
        
        // Resize array to actual count
        accountNullifiers = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            accountNullifiers[i] = temp[i];
        }
        
        return accountNullifiers;
    }

    /**
     * @dev Get total nullifiers used
     * @return Total number of nullifiers marked as used
     */
    function getTotalNullifiersUsed() external view returns (uint256) {
        return totalNullifiersUsed;
    }

    /**
     * @dev Emergency clear all nullifiers (use with extreme caution)
     * @dev This is for emergency situations only and should be used very carefully
     */
    function emergencyClearAllNullifiers() external onlyOwner {
        // This would require careful implementation in production
        // For now, it's a placeholder for emergency situations
        totalNullifiersUsed = 0;
        emit TrackerCleared(msg.sender);
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
     * @dev Verify nullifier hasn't been used and is properly formatted
     * @param nullifier Nullifier to verify
     * @return True if nullifier is valid and unused
     */
    function verifyNullifier(bytes32 nullifier) external view returns (bool) {
        if (nullifier == bytes32(0)) {
            return false;
        }
        
        if (usedNullifiers[nullifier]) {
            return false;
        }
        
        return true;
    }

    /**
     * @dev Get nullifier usage statistics
     * @return totalUsed Total nullifiers used
     * @return currentTimestamp Current block timestamp
     */
    function getUsageStatistics() external view returns (
        uint256 totalUsed,
        uint256 currentTimestamp
    ) {
        return (totalNullifiersUsed, block.timestamp);
    }
}