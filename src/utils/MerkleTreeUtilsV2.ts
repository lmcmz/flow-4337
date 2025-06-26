/**
 * @file MerkleTreeUtilsV2.ts
 * @description Utility functions for KeyInfo-based Merkle tree operations
 */

import { ethers } from 'ethers';
import { MerkleTree as MerkleTreeJS } from 'merkletreejs';
import {
    KeyInfo,
    KeyInfoMerkleTree,
    KeyInfoLeaf,
    FlowControlledErrorV2,
    FlowControlledAccountErrorV2
} from '../types/flow-controlled-v2';

export class MerkleTreeUtils {
    /**
     * Create KeyInfo hash for Merkle tree leaf
     */
    static createKeyInfoHash(keyInfo: KeyInfo): string {
        return ethers.utils.keccak256(
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
    }

    /**
     * Build Merkle tree from KeyInfo structs
     */
    static async buildKeyInfoMerkleTree(
        flowAddress: string,
        keyInfos: KeyInfo[],
        blockHeight: number
    ): Promise<KeyInfoMerkleTree> {
        if (keyInfos.length === 0) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_FLOW_ADDRESS,
                `No KeyInfo provided for Flow address: ${flowAddress}`
            );
        }

        // Sort keys by keyIndex to maintain Flow account order
        const sortedKeys = keyInfos.sort((a, b) => a.keyIndex - b.keyIndex);

        // Create leaves with KeyInfo hashes
        const leaves: KeyInfoLeaf[] = sortedKeys.map((keyInfo, index) => {
            const keyInfoHash = this.createKeyInfoHash(keyInfo);

            return {
                keyInfo,
                keyInfoHash,
                leafIndex: index
            };
        });

        // Build Merkle tree using KeyInfo hashes
        const leafHashes = leaves.map(leaf => leaf.keyInfoHash);
        const tree = new MerkleTreeJS(leafHashes, ethers.utils.keccak256, {
            sortPairs: true,
            duplicateOdd: true
        });

        // Generate proofs for all leaves
        const proofs: { [keyInfoHash: string]: string[] } = {};
        leaves.forEach(leaf => {
            const proof = tree.getHexProof(leaf.keyInfoHash);
            proofs[leaf.keyInfoHash] = proof;
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
     * Verify KeyInfo Merkle proof
     */
    static verifyKeyInfoProof(
        keyInfoHash: string,
        proof: string[],
        root: string
    ): boolean {
        let computedHash = keyInfoHash;

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
     * Get proof for a specific KeyInfo
     */
    static getProofForKeyInfo(
        merkleTree: KeyInfoMerkleTree,
        keyInfo: KeyInfo
    ): string[] {
        const keyInfoHash = this.createKeyInfoHash(keyInfo);
        const proof = merkleTree.proofs[keyInfoHash];
        
        if (!proof) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_KEY_INFO,
                `KeyInfo not found in Merkle tree`
            );
        }

        return proof;
    }

    /**
     * Validate KeyInfo-based Merkle tree structure
     */
    static validateKeyInfoMerkleTree(merkleTree: KeyInfoMerkleTree): boolean {
        try {
            // Check that all leaves have proofs
            for (const leaf of merkleTree.leaves) {
                const proof = merkleTree.proofs[leaf.keyInfoHash];
                if (!proof) {
                    return false;
                }

                // Verify each proof
                if (!this.verifyKeyInfoProof(leaf.keyInfoHash, proof, merkleTree.root)) {
                    return false;
                }
            }

            // Check key ordering (should be sorted by keyIndex)
            for (let i = 1; i < merkleTree.leaves.length; i++) {
                if (merkleTree.leaves[i].keyInfo.keyIndex < merkleTree.leaves[i - 1].keyInfo.keyIndex) {
                    return false;
                }
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Compare two KeyInfo-based Merkle trees
     */
    static compareKeyInfoMerkleTrees(tree1: KeyInfoMerkleTree, tree2: KeyInfoMerkleTree): {
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
            
            if (leaf1.keyInfoHash !== leaf2.keyInfoHash) {
                leavesMatch = false;
                differences.push(`Leaf ${i} KeyInfo hash mismatch: ${leaf1.keyInfoHash} vs ${leaf2.keyInfoHash}`);
            }
            
            if (!this.keyInfosEqual(leaf1.keyInfo, leaf2.keyInfo)) {
                differences.push(`Leaf ${i} KeyInfo content mismatch`);
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
     * Check if two KeyInfo structs are equal
     */
    static keyInfosEqual(keyInfo1: KeyInfo, keyInfo2: KeyInfo): boolean {
        return (
            keyInfo1.publicKey === keyInfo2.publicKey &&
            keyInfo1.weight === keyInfo2.weight &&
            keyInfo1.hashAlgorithm === keyInfo2.hashAlgorithm &&
            keyInfo1.signatureAlgorithm === keyInfo2.signatureAlgorithm &&
            keyInfo1.isRevoked === keyInfo2.isRevoked &&
            keyInfo1.keyIndex === keyInfo2.keyIndex
        );
    }

    /**
     * Validate KeyInfo structure
     */
    static validateKeyInfo(keyInfo: KeyInfo): boolean {
        try {
            // Validate public key (should be 64 bytes hex)
            if (!keyInfo.publicKey || typeof keyInfo.publicKey !== 'string') {
                return false;
            }
            
            const cleanKey = keyInfo.publicKey.replace('0x', '');
            if (!/^[0-9a-fA-F]{128}$/.test(cleanKey)) {
                return false;
            }

            // Validate weight (0-1000)
            if (typeof keyInfo.weight !== 'number' || keyInfo.weight < 0 || keyInfo.weight > 1000) {
                return false;
            }

            // Validate algorithms
            if (![1, 2].includes(keyInfo.hashAlgorithm) || ![1, 2].includes(keyInfo.signatureAlgorithm)) {
                return false;
            }

            // Validate key index
            if (typeof keyInfo.keyIndex !== 'number' || keyInfo.keyIndex < 0) {
                return false;
            }

            return true;
        } catch (error) {
            return false;
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
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INVALID_KEY_INFO,
                `Invalid public key length after formatting: ${cleanKey.length}, expected 128 hex characters`
            );
        }
        
        return cleanKey;
    }

    /**
     * Calculate total weight of active keys
     */
    static calculateTotalWeight(keyInfos: KeyInfo[]): number {
        return keyInfos
            .filter(key => !key.isRevoked)
            .reduce((sum, key) => sum + key.weight, 0);
    }

    /**
     * Check if keys meet weight threshold
     */
    static meetsWeightThreshold(keyInfos: KeyInfo[], threshold: number = 1000): boolean {
        const totalWeight = this.calculateTotalWeight(keyInfos);
        return totalWeight >= threshold;
    }

    /**
     * Find minimum keys needed to meet threshold
     */
    static findMinimumKeysForThreshold(
        keyInfos: KeyInfo[], 
        threshold: number = 1000
    ): KeyInfo[] {
        const activeKeys = keyInfos.filter(key => !key.isRevoked);
        
        // Sort by weight descending to minimize number of keys
        const sortedKeys = activeKeys.sort((a, b) => b.weight - a.weight);
        
        const selectedKeys: KeyInfo[] = [];
        let totalWeight = 0;

        for (const key of sortedKeys) {
            selectedKeys.push(key);
            totalWeight += key.weight;
            
            if (totalWeight >= threshold) {
                break;
            }
        }

        if (totalWeight < threshold) {
            throw new FlowControlledAccountErrorV2(
                FlowControlledErrorV2.INSUFFICIENT_SIGNATURE_WEIGHT,
                `Cannot meet weight threshold: ${totalWeight} < ${threshold}`
            );
        }

        return selectedKeys;
    }

    /**
     * Get keys by signature algorithm
     */
    static getKeysByAlgorithm(keyInfos: KeyInfo[], algorithm: number): KeyInfo[] {
        return keyInfos.filter(key => 
            !key.isRevoked && key.signatureAlgorithm === algorithm
        );
    }
}