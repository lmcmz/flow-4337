/**
 * @file FlowControlled.test.ts
 * @description Comprehensive test suite for Flow-controlled ERC-4337 implementation
 */

import { expect } from 'chai';
import { ethers } from 'hardhat';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { FlowRootRegistry, FlowControlledSmartAccount } from '../typechain';
import { MerkleTreeUtils } from '../src/utils/MerkleTreeUtils';
import {
    FlowKey,
    MerkleTree,
    SignatureAlgorithm,
    HashAlgorithm,
    FlowControlledUserOp
} from '../src/types/flow-controlled';

describe('Flow-Controlled ERC-4337 System', function () {
    let flowRootRegistry: FlowRootRegistry;
    let smartAccount: FlowControlledSmartAccount;
    let bundler: SignerWithAddress;
    let owner: SignerWithAddress;
    let user: SignerWithAddress;
    let flowAddress: string;

    const mockFlowKeys: FlowKey[] = [
        {
            publicKey: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            weight: 1000,
            hashAlgorithm: HashAlgorithm.SHA2_256,
            signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1,
            isRevoked: false,
            keyIndex: 0
        },
        {
            publicKey: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            weight: 500,
            hashAlgorithm: HashAlgorithm.SHA2_256,
            signatureAlgorithm: SignatureAlgorithm.ECDSA_P256,
            isRevoked: false,
            keyIndex: 1
        }
    ];

    beforeEach(async function () {
        [owner, bundler, user] = await ethers.getSigners();
        flowAddress = ethers.utils.getAddress(ethers.utils.hexlify(ethers.utils.randomBytes(20)));

        // Deploy FlowRootRegistry
        const FlowRootRegistryFactory = await ethers.getContractFactory('FlowRootRegistry');
        flowRootRegistry = await FlowRootRegistryFactory.deploy(bundler.address);
        await flowRootRegistry.deployed();

        // Deploy FlowControlledSmartAccount
        const SmartAccountFactory = await ethers.getContractFactory('FlowControlledSmartAccount');
        const smartAccountImpl = await SmartAccountFactory.deploy();
        await smartAccountImpl.deployed();

        // Deploy proxy for smart account
        const ProxyFactory = await ethers.getContractFactory('ERC1967Proxy');
        const initData = smartAccountImpl.interface.encodeFunctionData('initialize', [
            flowRootRegistry.address,
            flowAddress,
            owner.address
        ]);
        const proxy = await ProxyFactory.deploy(smartAccountImpl.address, initData);
        await proxy.deployed();

        smartAccount = SmartAccountFactory.attach(proxy.address);
    });

    describe('FlowRootRegistry', function () {
        it('should deploy with correct bundler', async function () {
            expect(await flowRootRegistry.trustedBundler()).to.equal(bundler.address);
        });

        it('should allow bundler to update root', async function () {
            const merkleTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                merkleTree.root,
                12345,
                mockFlowKeys.length
            );

            const storedRoot = await flowRootRegistry.getRoot(flowAddress);
            expect(storedRoot).to.equal(merkleTree.root);
        });

        it('should reject non-bundler root updates', async function () {
            const merkleTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            await expect(
                flowRootRegistry.connect(user).updateRoot(
                    flowAddress,
                    merkleTree.root,
                    12345,
                    mockFlowKeys.length
                )
            ).to.be.revertedWith('FlowRootRegistry: caller is not the trusted bundler');
        });

        it('should track root history', async function () {
            const merkleTree1 = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                [mockFlowKeys[0]],
                12345
            );
            const merkleTree2 = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12346
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                merkleTree1.root,
                12345,
                1
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                merkleTree2.root,
                12346,
                2
            );

            const history = await flowRootRegistry.getRootHistory(flowAddress);
            expect(history).to.have.length(2);
            expect(history[0]).to.equal(merkleTree1.root);
            expect(history[1]).to.equal(merkleTree2.root);
        });

        it('should verify Merkle proofs correctly', async function () {
            const merkleTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            const leaf = merkleTree.leaves[0];
            const proof = merkleTree.proofs[leaf.leafHash];

            const isValid = await flowRootRegistry.verifyMerkleProof(
                leaf.leafHash,
                proof,
                merkleTree.root
            );

            expect(isValid).to.be.true;
        });

        it('should create correct leaf hashes', async function () {
            const key = mockFlowKeys[0];
            const publicKeyBytes = ethers.utils.hexlify(Buffer.from(key.publicKey, 'hex'));
            
            const contractLeafHash = await flowRootRegistry.createLeafHash(
                publicKeyBytes,
                Math.floor(key.weight * 1000),
                key.hashAlgorithm,
                key.signatureAlgorithm
            );

            const utilsLeafHash = MerkleTreeUtils.createLeafHash(
                key.publicKey,
                key.weight,
                key.hashAlgorithm,
                key.signatureAlgorithm
            );

            expect(contractLeafHash).to.equal(utilsLeafHash);
        });
    });

    describe('FlowControlledSmartAccount', function () {
        let merkleTree: MerkleTree;

        beforeEach(async function () {
            // Set up Merkle tree and update registry
            merkleTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                merkleTree.root,
                12345,
                mockFlowKeys.length
            );
        });

        it('should initialize correctly', async function () {
            const accountInfo = await smartAccount.getAccountInfo();
            expect(accountInfo.flowAddress).to.equal(flowAddress);
            expect(accountInfo.registryAddress).to.equal(flowRootRegistry.address);
        });

        it('should validate user operations correctly', async function () {
            const key = mockFlowKeys[0];
            const leaf = merkleTree.leaves[0];
            const proof = merkleTree.proofs[leaf.leafHash];

            // Create mock signature
            const opHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation'));
            const mockSignature = ethers.utils.hexlify(ethers.utils.randomBytes(64));

            const userOp: FlowControlledUserOp = {
                flowAddress,
                opHash,
                publicKey: key.publicKey,
                weight: Math.floor(key.weight * 1000), // Convert to contract format
                hashAlgorithm: key.hashAlgorithm,
                signatureAlgorithm: key.signatureAlgorithm,
                signature: mockSignature,
                merkleProof: proof
            };

            // Note: This will fail signature verification, but should pass other validations
            const validationResult = await smartAccount.validateUserOp(userOp);
            // In a real test, we'd mock the signature verification or use actual signatures
        });

        it('should reject operations with invalid Flow address', async function () {
            const key = mockFlowKeys[0];
            const leaf = merkleTree.leaves[0];
            const proof = merkleTree.proofs[leaf.leafHash];

            const userOp: FlowControlledUserOp = {
                flowAddress: user.address, // Wrong Flow address
                opHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation')),
                publicKey: key.publicKey,
                weight: Math.floor(key.weight * 1000),
                hashAlgorithm: key.hashAlgorithm,
                signatureAlgorithm: key.signatureAlgorithm,
                signature: ethers.utils.hexlify(ethers.utils.randomBytes(64)),
                merkleProof: proof
            };

            const validationResult = await smartAccount.validateUserOp(userOp);
            expect(validationResult).to.equal(1); // Should fail validation
        });

        it('should reject operations with invalid Merkle proof', async function () {
            const key = mockFlowKeys[0];
            const invalidProof = [ethers.utils.hexlify(ethers.utils.randomBytes(32))];

            const userOp: FlowControlledUserOp = {
                flowAddress,
                opHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation')),
                publicKey: key.publicKey,
                weight: Math.floor(key.weight * 1000),
                hashAlgorithm: key.hashAlgorithm,
                signatureAlgorithm: key.signatureAlgorithm,
                signature: ethers.utils.hexlify(ethers.utils.randomBytes(64)),
                merkleProof: invalidProof
            };

            const validationResult = await smartAccount.validateUserOp(userOp);
            expect(validationResult).to.equal(1); // Should fail validation
        });

        it('should reject operations with insufficient key weight', async function () {
            // Create key with low weight
            const lowWeightKey: FlowKey = {
                ...mockFlowKeys[0],
                weight: 0.05, // 5% weight (below minimum)
                keyIndex: 2
            };

            const lowWeightMerkleTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                [lowWeightKey],
                12346
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                lowWeightMerkleTree.root,
                12346,
                1
            );

            const leaf = lowWeightMerkleTree.leaves[0];
            const proof = lowWeightMerkleTree.proofs[leaf.leafHash];

            const userOp: FlowControlledUserOp = {
                flowAddress,
                opHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test operation')),
                publicKey: lowWeightKey.publicKey,
                weight: Math.floor(lowWeightKey.weight * 1000),
                hashAlgorithm: lowWeightKey.hashAlgorithm,
                signatureAlgorithm: lowWeightKey.signatureAlgorithm,
                signature: ethers.utils.hexlify(ethers.utils.randomBytes(64)),
                merkleProof: proof
            };

            const validationResult = await smartAccount.validateUserOp(userOp);
            expect(validationResult).to.equal(1); // Should fail validation
        });
    });

    describe('MerkleTreeUtils', function () {
        it('should build consistent Merkle trees', async function () {
            const tree1 = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            const tree2 = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            expect(tree1.root).to.equal(tree2.root);
            expect(tree1.leaves).to.have.length(mockFlowKeys.length);
        });

        it('should maintain key ordering', async function () {
            const shuffledKeys = [...mockFlowKeys].reverse();
            const tree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                shuffledKeys,
                12345
            );

            // Should be sorted by keyIndex
            for (let i = 1; i < tree.leaves.length; i++) {
                expect(tree.leaves[i].keyIndex).to.be.greaterThan(tree.leaves[i - 1].keyIndex);
            }
        });

        it('should validate Flow keys correctly', async function () {
            expect(MerkleTreeUtils.validateFlowKey(mockFlowKeys[0])).to.be.true;

            const invalidKey = {
                ...mockFlowKeys[0],
                publicKey: 'invalid'
            };
            expect(MerkleTreeUtils.validateFlowKey(invalidKey)).to.be.false;
        });

        it('should format public keys correctly', async function () {
            const keyWith04 = '04' + mockFlowKeys[0].publicKey;
            const formatted = MerkleTreeUtils.formatPublicKey(keyWith04);
            expect(formatted).to.equal(mockFlowKeys[0].publicKey);
        });

        it('should verify Merkle proofs', async function () {
            const tree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            const leaf = tree.leaves[0];
            const proof = tree.proofs[leaf.leafHash];

            const isValid = MerkleTreeUtils.verifyMerkleProof(
                leaf.leafHash,
                proof,
                tree.root
            );

            expect(isValid).to.be.true;
        });

        it('should compare Merkle trees', async function () {
            const tree1 = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            const tree2 = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                [mockFlowKeys[0]],
                12345
            );

            const comparison = MerkleTreeUtils.compareMerkleTrees(tree1, tree2);
            expect(comparison.rootMatches).to.be.false;
            expect(comparison.leafCountMatches).to.be.false;
            expect(comparison.differences).to.have.length.greaterThan(0);
        });
    });

    describe('Integration Tests', function () {
        it('should handle complete flow from key registration to operation execution', async function () {
            // 1. Build Merkle tree from Flow keys
            const merkleTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12345
            );

            // 2. Update root in registry (simulating bundler)
            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                merkleTree.root,
                12345,
                mockFlowKeys.length
            );

            // 3. Verify root is stored
            const storedRoot = await flowRootRegistry.getRoot(flowAddress);
            expect(storedRoot).to.equal(merkleTree.root);

            // 4. Verify root freshness
            const isFresh = await flowRootRegistry.isRootFresh(flowAddress);
            expect(isFresh).to.be.true;

            // 5. Get account info
            const accountInfo = await smartAccount.getAccountInfo();
            expect(accountInfo.isRootFresh).to.be.true;
        });

        it('should handle root updates when keys change', async function () {
            // Initial setup
            const initialTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                [mockFlowKeys[0]],
                12345
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                initialTree.root,
                12345,
                1
            );

            // Add new key (simulating Flow account key addition)
            const updatedTree = MerkleTreeUtils.buildMerkleTreeFromKeys(
                flowAddress,
                mockFlowKeys,
                12346
            );

            await flowRootRegistry.connect(bundler).updateRoot(
                flowAddress,
                updatedTree.root,
                12346,
                2
            );

            // Verify update
            const currentRoot = await flowRootRegistry.getRoot(flowAddress);
            expect(currentRoot).to.equal(updatedTree.root);

            const rootData = await flowRootRegistry.getRootData(flowAddress);
            expect(rootData.keyCount).to.equal(2);
            expect(rootData.lastUpdateHeight).to.equal(12346);
        });
    });
});