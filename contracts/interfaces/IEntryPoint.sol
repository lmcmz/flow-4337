// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IEntryPoint
 * @dev Interface for ERC-4337 Entry Point contract
 * Simplified interface for Flow-controlled accounts
 */
interface IEntryPoint {
    
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
    
    function simulateValidation(UserOperation calldata userOp) external returns (uint256 validationData);
    
    function getUserOpHash(UserOperation calldata userOp) external view returns (bytes32);
}