/**
 * @file MerkleTreeUtils.ts
 * @description Utility functions for Merkle tree operations
 */

import { ethers } from 'ethers';
import { MerkleTree as MerkleTreeJS } from 'merkletreejs';
import {
    FlowKey,
    MerkleTree,
    MerkleLeaf,
    FlowControlledError,
    FlowControlledAccountError
} from '../types/flow-controlled';

export class MerkleTreeUtils {
    /**
     * Create leaf hash from Flow key data
     */
    static createLeafHash(
        publicKey: string,
        weight: number,
        hashAlgorithm: number,
        signatureAlgorithm: number
    ): string {
        const publicKeyBytes = Buffer.from(publicKey, 'hex');
        const weightScaled = Math.floor(weight * 1000); // Convert to Flow's internal representation
        
        return ethers.utils.keccak256(
            ethers.utils.defaultAbiCoder.encode(
                ['bytes', 'uint256', 'uint8', 'uint8'],
                [publicKeyBytes, weightScaled, hashAlgorithm, signatureAlgorithm]
            )
        );
    }

    /**
     * Build Merkle tree from Flow keys
     */
    static buildMerkleTreeFromKeys(
        flowAddress: string,
        keys: FlowKey[],
        blockHeight: number
    ): MerkleTree {
        if (keys.length === 0) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_FLOW_ADDRESS,
                `No keys provided for Flow address: ${flowAddress}`
            );
        }

        // Sort keys by keyIndex to maintain Flow account order
        const sortedKeys = keys.sort((a, b) => a.keyIndex - b.keyIndex);

        // Create leaves
        const leaves: MerkleLeaf[] = sortedKeys.map(key => {
            const leafHash = this.createLeafHash(
                key.publicKey,
                key.weight,
                key.hashAlgorithm,
                key.signatureAlgorithm
            );

            return {
                publicKey: key.publicKey,
                weight: key.weight,
                hashAlgorithm: key.hashAlgorithm,
                signatureAlgorithm: key.signatureAlgorithm,
                keyIndex: key.keyIndex,
                leafHash
            };
        });

        // Build Merkle tree
        const leafHashes = leaves.map(leaf => leaf.leafHash);
        const tree = new MerkleTreeJS(leafHashes, ethers.utils.keccak256, {
            sortPairs: true,
            duplicateOdd: true
        });

        // Generate proofs for all leaves
        const proofs: { [leafHash: string]: string[] } = {};
        leaves.forEach(leaf => {
            const proof = tree.getHexProof(leaf.leafHash);
            proofs[leaf.leafHash] = proof;
        });

        return {
            root: tree.getHexRoot(),
            leaves,
            proofs,
            totalKeys: leaves.length,
            blockHeight,
            flowAddress
        };
    }

    /**
     * Verify Merkle proof
     */
    static verifyMerkleProof(
        leaf: string,
        proof: string[],
        root: string
    ): boolean {
        let computedHash = leaf;

        for (const proofElement of proof) {
            if (computedHash <= proofElement) {
                computedHash = ethers.utils.keccak256(
                    ethers.utils.solidityPack(['bytes32', 'bytes32'], [computedHash, proofElement])
                );
            } else {
                computedHash = ethers.utils.keccak256(
                    ethers.utils.solidityPack(['bytes32', 'bytes32'], [proofElement, computedHash])
                );
            }
        }

        return computedHash === root;
    }

    /**
     * Get proof for a specific public key
     */
    static getProofForKey(
        merkleTree: MerkleTree,
        publicKey: string
    ): string[] {
        const leaf = merkleTree.leaves.find(l => l.publicKey === publicKey);
        if (!leaf) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_PUBLIC_KEY,
                `Public key not found in Merkle tree: ${publicKey}`
            );
        }

        return merkleTree.proofs[leaf.leafHash];
    }

    /**
     * Validate Merkle tree structure
     */
    static validateMerkleTree(merkleTree: MerkleTree): boolean {
        try {
            // Check that all leaves have proofs
            for (const leaf of merkleTree.leaves) {
                const proof = merkleTree.proofs[leaf.leafHash];
                if (!proof) {
                    return false;
                }

                // Verify each proof
                if (!this.verifyMerkleProof(leaf.leafHash, proof, merkleTree.root)) {
                    return false;
                }
            }

            // Check key ordering (should be sorted by keyIndex)
            for (let i = 1; i < merkleTree.leaves.length; i++) {
                if (merkleTree.leaves[i].keyIndex < merkleTree.leaves[i - 1].keyIndex) {
                    return false;
                }
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Compare two Merkle trees
     */
    static compareMerkleTrees(tree1: MerkleTree, tree2: MerkleTree): {
        rootMatches: boolean;
        leafCountMatches: boolean;
        leavesMatch: boolean;
        differences: string[];
    } {
        const differences: string[] = [];
        
        const rootMatches = tree1.root === tree2.root;
        if (!rootMatches) {
            differences.push(`Root mismatch: ${tree1.root} vs ${tree2.root}`);
        }

        const leafCountMatches = tree1.leaves.length === tree2.leaves.length;
        if (!leafCountMatches) {
            differences.push(`Leaf count mismatch: ${tree1.leaves.length} vs ${tree2.leaves.length}`);
        }

        let leavesMatch = true;
        const minLength = Math.min(tree1.leaves.length, tree2.leaves.length);
        
        for (let i = 0; i < minLength; i++) {
            const leaf1 = tree1.leaves[i];
            const leaf2 = tree2.leaves[i];
            
            if (leaf1.leafHash !== leaf2.leafHash) {
                leavesMatch = false;
                differences.push(`Leaf ${i} hash mismatch: ${leaf1.leafHash} vs ${leaf2.leafHash}`);
            }
            
            if (leaf1.publicKey !== leaf2.publicKey) {
                differences.push(`Leaf ${i} public key mismatch: ${leaf1.publicKey} vs ${leaf2.publicKey}`);
            }
        }

        return {
            rootMatches,
            leafCountMatches,
            leavesMatch,
            differences
        };
    }

    /**
     * Convert public key to address for signature verification
     */
    static pubkeyToAddress(publicKey: string, signatureAlgorithm: number): string {
        const keyBytes = Buffer.from(publicKey, 'hex');
        
        if (keyBytes.length !== 64) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_PUBLIC_KEY,
                `Invalid public key length: ${keyBytes.length}, expected 64 bytes`
            );
        }

        if (signatureAlgorithm === 2) { // ECDSA_secp256k1
            // Standard Ethereum address derivation
            return ethers.utils.getAddress(ethers.utils.keccak256(keyBytes).slice(-40));
        } else if (signatureAlgorithm === 1) { // ECDSA_P256
            // P256 keys use a different derivation
            return ethers.utils.getAddress(
                ethers.utils.keccak256(
                    ethers.utils.solidityPack(['string', 'bytes'], ['P256:', keyBytes])
                ).slice(-40)
            );
        } else {
            throw new FlowControlledAccountError(
                FlowControlledError.UNSUPPORTED_ALGORITHM,
                `Unsupported signature algorithm: ${signatureAlgorithm}`
            );
        }
    }

    /**
     * Format public key (ensure no 04 prefix)
     */
    static formatPublicKey(publicKey: string): string {
        let cleanKey = publicKey.replace('0x', '');
        
        // Remove 04 prefix if present
        if (cleanKey.length === 130 && cleanKey.startsWith('04')) {
            cleanKey = cleanKey.slice(2);
        }
        
        if (cleanKey.length !== 128) {
            throw new FlowControlledAccountError(
                FlowControlledError.INVALID_PUBLIC_KEY,
                `Invalid public key length after formatting: ${cleanKey.length}, expected 128 hex characters`
            );
        }
        
        return cleanKey;
    }

    /**
     * Validate Flow key structure
     */
    static validateFlowKey(key: FlowKey): boolean {
        try {
            // Validate public key
            if (!key.publicKey || typeof key.publicKey !== 'string') {
                return false;
            }
            
            const formattedKey = this.formatPublicKey(key.publicKey);
            if (!/^[0-9a-fA-F]{128}$/.test(formattedKey)) {
                return false;
            }

            // Validate weight (should be between 0 and 1000)
            if (typeof key.weight !== 'number' || key.weight < 0 || key.weight > 1000) {
                return false;
            }

            // Validate algorithms
            if (![1, 2].includes(key.hashAlgorithm) || ![1, 2].includes(key.signatureAlgorithm)) {
                return false;
            }

            // Validate key index
            if (typeof key.keyIndex !== 'number' || key.keyIndex < 0) {
                return false;
            }

            return true;
        } catch (error) {
            return false;
        }
    }
}