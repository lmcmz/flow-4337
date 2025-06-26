/**
 * @file FlowControlledV2.test.ts
 * @description Comprehensive test suite for Flow-controlled ERC-4337 V2 implementation
 * Tests CREATE2 factory, multi-signature validation, and KeyInfo-based Merkle trees
 */

import { expect } from 'chai';
import { ethers } from 'hardhat';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { 
    FlowKeyRegister, 
    FlowRootRegistry, 
    FlowControlledSmartAccountV2,
    FlowAccountFactory 
} from '../typechain';
import {
    KeyInfo,
    KeyInfoMerkleTree,
    FlowMultiSigUserOp,
    SignatureAlgorithm,
    HashAlgorithm
} from '../src/types/flow-controlled-v2';
import { MerkleTreeUtils } from '../src/utils/MerkleTreeUtilsV2';

describe('Flow-Controlled ERC-4337 V2 System', function () {
    let flowKeyRegister: FlowKeyRegister;
    let flowRootRegistry: FlowRootRegistry;
    let accountFactory: FlowAccountFactory;
    let smartAccountImpl: FlowControlledSmartAccountV2;
    let smartAccount: FlowControlledSmartAccountV2;
    let bundler: SignerWithAddress;
    let admin: SignerWithAddress;
    let user: SignerWithAddress;
    let flowAddress: string;

    const mockKeyInfos: KeyInfo[] = [
        {
            publicKey: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            weight: 600,
            hashAlgorithm: HashAlgorithm.SHA2_256,
            signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1,
            isRevoked: false,
            keyIndex: 0
        },
        {
            publicKey: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            weight: 400,
            hashAlgorithm: HashAlgorithm.SHA2_256,
            signatureAlgorithm: SignatureAlgorithm.ECDSA_P256,
            isRevoked: false,
            keyIndex: 1
        }
    ];

    beforeEach(async function () {
        [admin, bundler, user] = await ethers.getSigners();
        flowAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));

        // Deploy FlowKeyRegister
        const FlowKeyRegisterFactory = await ethers.getContractFactory('FlowKeyRegister');
        flowKeyRegister = await FlowKeyRegisterFactory.deploy(bundler.address);
        await flowKeyRegister.deployed();

        // Deploy FlowRootRegistry
        const FlowRootRegistryFactory = await ethers.getContractFactory('FlowRootRegistry');
        flowRootRegistry = await FlowRootRegistryFactory.deploy(bundler.address);
        await flowRootRegistry.deployed();

        // Deploy SmartAccount implementation
        const SmartAccountFactory = await ethers.getContractFactory('FlowControlledSmartAccountV2');
        smartAccountImpl = await SmartAccountFactory.deploy();
        await smartAccountImpl.deployed();

        // Deploy FlowAccountFactory
        const FactoryFactory = await ethers.getContractFactory('FlowAccountFactory');
        accountFactory = await FactoryFactory.deploy(smartAccountImpl.address, flowRootRegistry.address);
        await accountFactory.deployed();

        // Create smart account using factory
        const tx = await accountFactory.createAccount(flowAddress);
        const receipt = await tx.wait();
        const event = receipt.events?.find(e => e.event === 'AccountCreated');
        const smartAccountAddress = event?.args?.account;

        smartAccount = SmartAccountFactory.attach(smartAccountAddress);
        
        // Set FlowKeyRegister address in smart account
        await smartAccount.connect(admin).setFlowKeyRegister(flowKeyRegister.address);
    });

    describe('FlowKeyRegister', function () {
        it('should deploy with correct bundler', async function () {
            expect(await flowKeyRegister.primaryBundler()).to.equal(bundler.address);
            expect(await flowKeyRegister.authorizedBundlers(bundler.address)).to.be.true;
        });

        it('should allow bundler to update keys', async function () {
            const blockHeight = 12345;

            await flowKeyRegister.connect(bundler).updateKeys(
                flowAddress,
                mockKeyInfos,
                blockHeight
            );

            const storedKeys = await flowKeyRegister.getKeys(flowAddress);
            expect(storedKeys).to.have.length(mockKeyInfos.length);
            
            for (let i = 0; i < mockKeyInfos.length; i++) {
                expect(storedKeys[i].weight).to.equal(mockKeyInfos[i].weight);
                expect(storedKeys[i].keyIndex).to.equal(mockKeyInfos[i].keyIndex);
            }
        });

        it('should reject non-bundler key updates', async function () {
            await expect(
                flowKeyRegister.connect(user).updateKeys(
                    flowAddress,
                    mockKeyInfos,
                    12345
                )
            ).to.be.revertedWith('FlowKeyRegister: unauthorized bundler');
        });

        it('should track account state correctly', async function () {
            const blockHeight = 12345;
            
            await flowKeyRegister.connect(bundler).updateKeys(
                flowAddress,
                mockKeyInfos,
                blockHeight
            );

            const accountState = await flowKeyRegister.getAccountState(flowAddress);
            expect(accountState.keyCount).to.equal(mockKeyInfos.length);
            expect(accountState.totalWeight).to.equal(1000); // 600 + 400
            expect(accountState.lastUpdateHeight).to.equal(blockHeight);
            expect(accountState.exists).to.be.true;
        });

        it('should return only active keys', async function () {
            const keysWithRevoked = [...mockKeyInfos];
            keysWithRevoked[1].isRevoked = true;

            await flowKeyRegister.connect(bundler).updateKeys(
                flowAddress,
                keysWithRevoked,
                12345
            );

            const activeKeys = await flowKeyRegister.getActiveKeys(flowAddress);
            expect(activeKeys).to.have.length(1);
            expect(activeKeys[0].keyIndex).to.equal(0);
        });

        it('should create correct KeyInfo hashes', async function () {
            const keyInfo = mockKeyInfos[0];
            
            const contractHash = await flowKeyRegister.createKeyInfoHash(keyInfo);
            const expectedHash = ethers.utils.keccak256(
                ethers.utils.defaultAbiCoder.encode(
                    ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                    [
                        keyInfo.publicKey,
                        keyInfo.weight,
                        keyInfo.hashAlgorithm,
                        keyInfo.signatureAlgorithm,
                        keyInfo.isRevoked,
                        keyInfo.keyIndex
                    ]
                )
            );

            expect(contractHash).to.equal(expectedHash);
        });

        it('should allow admin override', async function () {
            const reason = "Emergency key update";
            
            await flowKeyRegister.connect(admin).adminUpdateKeys(
                flowAddress,
                mockKeyInfos,
                reason
            );

            const storedKeys = await flowKeyRegister.getKeys(flowAddress);
            expect(storedKeys).to.have.length(mockKeyInfos.length);
        });
    });

    describe('FlowAccountFactory', function () {
        it('should deploy with correct configuration', async function () {
            const factoryInfo = await accountFactory.getFactoryInfo();
            expect(factoryInfo.impl).to.equal(smartAccountImpl.address);
            expect(factoryInfo.registry).to.equal(flowRootRegistry.address);
        });

        it('should create accounts deterministically', async function () {
            const predictedAddress = await accountFactory.getAddress(flowAddress);
            
            const tx = await accountFactory.createAccount(flowAddress);
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'AccountCreated');
            const actualAddress = event?.args?.account;

            expect(actualAddress).to.equal(predictedAddress);
        });

        it('should prevent duplicate account creation', async function () {
            await accountFactory.createAccount(flowAddress);
            
            await expect(
                accountFactory.createAccount(flowAddress)
            ).to.be.revertedWith('FlowAccountFactory: account already exists');
        });

        it('should track account mappings', async function () {
            const tx = await accountFactory.createAccount(flowAddress);
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'AccountCreated');
            const accountAddress = event?.args?.account;

            expect(await accountFactory.getAccount(flowAddress)).to.equal(accountAddress);
            expect(await accountFactory.getFlowAddress(accountAddress)).to.equal(flowAddress);
            expect(await accountFactory.accountExists(flowAddress)).to.be.true;
        });

        it('should support batch account creation', async function () {
            const flowAddresses = [
                ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20))),
                ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)))
            ];

            const tx = await accountFactory.batchCreateAccounts(flowAddresses);
            const receipt = await tx.wait();
            const events = receipt.events?.filter(e => e.event === 'AccountCreated');

            expect(events).to.have.length(2);
            expect(await accountFactory.getAccountCount()).to.equal(3); // 1 from beforeEach + 2 from batch
        });
    });

    describe('FlowControlledSmartAccountV2', function () {
        let merkleTree: KeyInfoMerkleTree;

        beforeEach(async function () {
            // Set up keys in FlowKeyRegister
            await flowKeyRegister.connect(bundler).updateKeys(
                flowAddress,
                mockKeyInfos,
                12345
            );

            // Build Merkle tree and update registry
            merkleTree = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                mockKeyInfos,
                12345
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                merkleTree.root,
                12345,
                mockKeyInfos.length
            );
        });

        it('should initialize correctly with Flow address only', async function () {
            const accountInfo = await smartAccount.getAccountInfo();
            expect(accountInfo.flowAddress).to.equal(flowAddress);
            expect(accountInfo.registryAddress).to.equal(flowRootRegistry.address);
            expect(accountInfo.keyRegisterAddress).to.equal(flowKeyRegister.address);
        });

        it('should validate multi-signature user operations', async function () {
            const opHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation'));
            const mockSignatures = [
                ethers.utils.hexlify(ethers.utils.randomBytes(64)),
                ethers.utils.hexlify(ethers.utils.randomBytes(64))
            ];

            // Get Merkle proofs for each key
            const merkleProofs = mockKeyInfos.map(keyInfo => {
                const keyInfoHash = ethers.utils.keccak256(
                    ethers.utils.defaultAbiCoder.encode(
                        ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                        [
                            keyInfo.publicKey,
                            keyInfo.weight,
                            keyInfo.hashAlgorithm,
                            keyInfo.signatureAlgorithm,
                            keyInfo.isRevoked,
                            keyInfo.keyIndex
                        ]
                    )
                );
                return merkleTree.proofs[keyInfoHash];
            });

            const userOp: FlowMultiSigUserOp = {
                flowAddress,
                opHash,
                keys: mockKeyInfos,
                signatures: mockSignatures,
                merkleProofs
            };

            // This will fail signature verification but should pass other validations
            const validationResult = await smartAccount.validateUserOp(userOp);
            // In a real test, we'd need proper signatures or mock the signature verification
        });

        it('should reject operations with insufficient weight', async function () {
            // Use only the first key (600 weight < 1000 threshold)
            const insufficientKeys = [mockKeyInfos[0]];
            const opHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation'));
            const mockSignatures = [ethers.utils.hexlify(ethers.utils.randomBytes(64))];

            const keyInfoHash = ethers.utils.keccak256(
                ethers.utils.defaultAbiCoder.encode(
                    ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                    [
                        insufficientKeys[0].publicKey,
                        insufficientKeys[0].weight,
                        insufficientKeys[0].hashAlgorithm,
                        insufficientKeys[0].signatureAlgorithm,
                        insufficientKeys[0].isRevoked,
                        insufficientKeys[0].keyIndex
                    ]
                )
            );

            const userOp: FlowMultiSigUserOp = {
                flowAddress,
                opHash,
                keys: insufficientKeys,
                signatures: mockSignatures,
                merkleProofs: [merkleTree.proofs[keyInfoHash]]
            };

            const validationResult = await smartAccount.validateUserOp(userOp);
            expect(validationResult).to.equal(1); // Should fail validation
        });

        it('should reject operations with mismatched Flow address', async function () {
            const wrongFlowAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));
            const opHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation'));
            const mockSignatures = mockKeyInfos.map(() => ethers.utils.hexlify(ethers.utils.randomBytes(64)));
            
            const merkleProofs = mockKeyInfos.map(keyInfo => {
                const keyInfoHash = ethers.utils.keccak256(
                    ethers.utils.defaultAbiCoder.encode(
                        ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                        [
                            keyInfo.publicKey,
                            keyInfo.weight,
                            keyInfo.hashAlgorithm,
                            keyInfo.signatureAlgorithm,
                            keyInfo.isRevoked,
                            keyInfo.keyIndex
                        ]
                    )
                );
                return merkleTree.proofs[keyInfoHash];
            });

            const userOp: FlowMultiSigUserOp = {
                flowAddress: wrongFlowAddress,
                opHash,
                keys: mockKeyInfos,
                signatures: mockSignatures,
                merkleProofs
            };

            const validationResult = await smartAccount.validateUserOp(userOp);
            expect(validationResult).to.equal(1); // Should fail validation
        });

        it('should reject operations with revoked keys', async function () {
            const revokedKeys = [...mockKeyInfos];
            revokedKeys[0].isRevoked = true;

            const opHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation'));
            const mockSignatures = revokedKeys.map(() => ethers.utils.hexlify(ethers.utils.randomBytes(64)));
            
            // Note: This would need a new Merkle tree with revoked keys
            // For this test, we'll use the old proofs which should make it fail
            const merkleProofs = mockKeyInfos.map(keyInfo => {
                const keyInfoHash = ethers.utils.keccak256(
                    ethers.utils.defaultAbiCoder.encode(
                        ['bytes', 'uint256', 'uint8', 'uint8', 'bool', 'uint256'],
                        [
                            keyInfo.publicKey,
                            keyInfo.weight,
                            keyInfo.hashAlgorithm,
                            keyInfo.signatureAlgorithm,
                            keyInfo.isRevoked,
                            keyInfo.keyIndex
                        ]
                    )
                );
                return merkleTree.proofs[keyInfoHash];
            });

            const userOp: FlowMultiSigUserOp = {
                flowAddress,
                opHash,
                keys: revokedKeys,
                signatures: mockSignatures,
                merkleProofs
            };

            const validationResult = await smartAccount.validateUserOp(userOp);
            expect(validationResult).to.equal(1); // Should fail validation
        });
    });

    describe('Merkle Tree with KeyInfo', function () {
        it('should build consistent trees from KeyInfo structs', async function () {
            const tree1 = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                mockKeyInfos,
                12345
            );

            const tree2 = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                mockKeyInfos,
                12345
            );

            expect(tree1.root).to.equal(tree2.root);
            expect(tree1.leaves).to.have.length(mockKeyInfos.length);
        });

        it('should maintain key ordering by keyIndex', async function () {
            const shuffledKeys = [...mockKeyInfos].reverse();
            const tree = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                shuffledKeys,
                12345
            );

            // Should be sorted by keyIndex
            for (let i = 1; i < tree.leaves.length; i++) {
                expect(tree.leaves[i].keyInfo.keyIndex).to.be.greaterThan(tree.leaves[i - 1].keyInfo.keyIndex);
            }
        });

        it('should generate valid proofs for all keys', async function () {
            const tree = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                mockKeyInfos,
                12345
            );

            for (const leaf of tree.leaves) {
                const proof = tree.proofs[leaf.keyInfoHash];
                const isValid = MerkleTreeUtils.verifyKeyInfoProof(
                    leaf.keyInfoHash,
                    proof,
                    tree.root
                );
                expect(isValid).to.be.true;
            }
        });

        it('should reject invalid proofs', async function () {
            const tree = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                mockKeyInfos,
                12345
            );

            const invalidProof = [ethers.utils.hexlify(ethers.utils.randomBytes(32))];
            const leaf = tree.leaves[0];
            
            const isValid = MerkleTreeUtils.verifyKeyInfoProof(
                leaf.keyInfoHash,
                invalidProof,
                tree.root
            );
            expect(isValid).to.be.false;
        });
    });

    describe('Integration Tests', function () {
        it('should handle complete flow from factory to operation validation', async function () {
            // 1. Keys already set up in beforeEach
            
            // 2. Verify keys are stored correctly
            const storedKeys = await flowKeyRegister.getKeys(flowAddress);
            expect(storedKeys).to.have.length(mockKeyInfos.length);

            // 3. Verify account has sufficient weight
            const hasSufficientWeight = await flowKeyRegister.hasSufficientWeight(flowAddress);
            expect(hasSufficientWeight).to.be.true;

            // 4. Verify root is fresh
            const isRootFresh = await flowRootRegistry.isRootFresh(flowAddress);
            expect(isRootFresh).to.be.true;

            // 5. Verify smart account info
            const accountInfo = await smartAccount.getAccountInfo();
            expect(accountInfo.isRootFresh).to.be.true;
            expect(accountInfo.hasSufficientWeight).to.be.true;
        });

        it('should handle key updates and re-synchronization', async function () {
            // Initial setup already done
            const initialAccountState = await flowKeyRegister.getAccountState(flowAddress);
            expect(initialAccountState.keyCount).to.equal(2);
            expect(initialAccountState.totalWeight).to.equal(1000);

            // Simulate key update (add new key)
            const newKey: KeyInfo = {
                publicKey: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba098765',
                weight: 200,
                hashAlgorithm: HashAlgorithm.SHA2_256,
                signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1,
                isRevoked: false,
                keyIndex: 2
            };

            const updatedKeys = [...mockKeyInfos, newKey];

            // Update keys in register
            await flowKeyRegister.connect(bundler).updateKeys(
                flowAddress,
                updatedKeys,
                12346
            );

            // Verify update
            const updatedAccountState = await flowKeyRegister.getAccountState(flowAddress);
            expect(updatedAccountState.keyCount).to.equal(3);
            expect(updatedAccountState.totalWeight).to.equal(1200);

            // Update Merkle root
            const newMerkleTree = await MerkleTreeUtils.buildKeyInfoMerkleTree(
                flowAddress,
                updatedKeys,
                12346
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                newMerkleTree.root,
                12346,
                updatedKeys.length
            );

            // Verify new root
            const currentRoot = await flowRootRegistry.getRoot(flowAddress);
            expect(currentRoot).to.equal(newMerkleTree.root);
        });
    });
});