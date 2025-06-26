// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title FlowAccountFactory
 * @dev CREATE2 factory for deterministic deployment of Flow-controlled ERC-4337 accounts
 * @notice Deploys smart accounts using only Flow address, no EVM owner required
 */
contract FlowAccountFactory is Ownable, ReentrancyGuard {
    
    // Events
    event AccountCreated(
        address indexed flowAddress,
        address indexed account,
        bytes32 indexed salt
    );
    
    event ImplementationUpdated(
        address indexed oldImplementation,
        address indexed newImplementation
    );

    // Smart account implementation address
    address public immutable accountImplementation;
    
    // Flow root registry address
    address public immutable flowRootRegistry;
    
    // Mapping to track created accounts
    mapping(address => address) public flowToAccount;
    mapping(address => address) public accountToFlow;
    
    // Array of all created accounts for enumeration
    address[] public allAccounts;

    constructor(
        address _accountImplementation,
        address _flowRootRegistry
    ) {
        require(_accountImplementation != address(0), "FlowAccountFactory: invalid implementation");
        require(_flowRootRegistry != address(0), "FlowAccountFactory: invalid registry");
        
        accountImplementation = _accountImplementation;
        flowRootRegistry = _flowRootRegistry;
    }

    /**
     * @dev Create a new Flow-controlled smart account using CREATE2
     * @param flowAddress Flow blockchain address that will control this account
     * @return account Address of the created smart account
     */
    function createAccount(address flowAddress) external nonReentrant returns (address account) {
        require(flowAddress != address(0), "FlowAccountFactory: invalid Flow address");
        require(flowToAccount[flowAddress] == address(0), "FlowAccountFactory: account already exists");

        // Generate deterministic salt from Flow address
        bytes32 salt = _generateSalt(flowAddress);
        
        // Deploy using CREATE2 for deterministic address
        account = Clones.cloneDeterministic(accountImplementation, salt);
        
        // Initialize the account (only takes Flow address, no EVM owner)
        IFlowControlledSmartAccount(account).initialize(
            flowRootRegistry,
            flowAddress
        );
        
        // Track the mapping
        flowToAccount[flowAddress] = account;
        accountToFlow[account] = flowAddress;
        allAccounts.push(account);
        
        emit AccountCreated(flowAddress, account, salt);
        
        return account;
    }

    /**
     * @dev Get the deterministic address for a Flow address (before deployment)
     * @param flowAddress Flow blockchain address
     * @return account Predicted address of the smart account
     */
    function getAddress(address flowAddress) external view returns (address account) {
        require(flowAddress != address(0), "FlowAccountFactory: invalid Flow address");
        
        bytes32 salt = _generateSalt(flowAddress);
        return Clones.predictDeterministicAddress(accountImplementation, salt, address(this));
    }

    /**
     * @dev Check if an account exists for a Flow address
     * @param flowAddress Flow blockchain address
     * @return exists True if account exists
     */
    function accountExists(address flowAddress) external view returns (bool exists) {
        return flowToAccount[flowAddress] != address(0);
    }

    /**
     * @dev Get smart account address for a Flow address
     * @param flowAddress Flow blockchain address
     * @return account Smart account address (zero if not created)
     */
    function getAccount(address flowAddress) external view returns (address account) {
        return flowToAccount[flowAddress];
    }

    /**
     * @dev Get Flow address for a smart account
     * @param account Smart account address
     * @return flowAddress Flow blockchain address (zero if not found)
     */
    function getFlowAddress(address account) external view returns (address flowAddress) {
        return accountToFlow[account];
    }

    /**
     * @dev Get total number of created accounts
     * @return count Number of accounts
     */
    function getAccountCount() external view returns (uint256 count) {
        return allAccounts.length;
    }

    /**
     * @dev Get account address by index
     * @param index Account index
     * @return account Account address at index
     */
    function getAccountByIndex(uint256 index) external view returns (address account) {
        require(index < allAccounts.length, "FlowAccountFactory: index out of bounds");
        return allAccounts[index];
    }

    /**
     * @dev Batch create accounts for multiple Flow addresses
     * @param flowAddresses Array of Flow addresses
     * @return accounts Array of created account addresses
     */
    function batchCreateAccounts(
        address[] calldata flowAddresses
    ) external nonReentrant returns (address[] memory accounts) {
        require(flowAddresses.length > 0, "FlowAccountFactory: empty array");
        require(flowAddresses.length <= 20, "FlowAccountFactory: batch too large");
        
        accounts = new address[](flowAddresses.length);
        
        for (uint256 i = 0; i < flowAddresses.length; i++) {
            require(flowAddresses[i] != address(0), "FlowAccountFactory: invalid Flow address");
            require(flowToAccount[flowAddresses[i]] == address(0), "FlowAccountFactory: account already exists");
            
            bytes32 salt = _generateSalt(flowAddresses[i]);
            address account = Clones.cloneDeterministic(accountImplementation, salt);
            
            IFlowControlledSmartAccount(account).initialize(
                flowRootRegistry,
                flowAddresses[i]
            );
            
            flowToAccount[flowAddresses[i]] = account;
            accountToFlow[account] = flowAddresses[i];
            allAccounts.push(account);
            accounts[i] = account;
            
            emit AccountCreated(flowAddresses[i], account, salt);
        }
        
        return accounts;
    }

    /**
     * @dev Generate deterministic salt from Flow address
     * @param flowAddress Flow blockchain address
     * @return salt Deterministic salt for CREATE2
     */
    function _generateSalt(address flowAddress) internal pure returns (bytes32 salt) {
        return keccak256(abi.encode("FlowControlled", flowAddress));
    }

    /**
     * @dev Get factory configuration
     * @return impl Implementation address
     * @return registry Registry address  
     * @return totalAccounts Total accounts created
     */
    function getFactoryInfo() external view returns (
        address impl,
        address registry,
        uint256 totalAccounts
    ) {
        return (accountImplementation, flowRootRegistry, allAccounts.length);
    }
}

/**
 * @title IFlowControlledSmartAccount
 * @dev Interface for Flow-controlled smart account initialization
 */
interface IFlowControlledSmartAccount {
    function initialize(
        address flowRootRegistry,
        address flowAddress
    ) external;
}