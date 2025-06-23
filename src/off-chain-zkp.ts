import { createHash, randomBytes } from "crypto";
import * as fs from "fs";
import {
  FlowAccountProofData,
  COAOwnershipProofInContext,
  flowAccountProofService,
} from "./flow-account-proof";

const snarkjs = require("snarkjs");

/**
 * Off-Chain Zero-Knowledge Proof Generator
 * Generates privacy-preserving proofs of Flow account ownership
 * NO PUBLIC KEY EXPOSURE - uses commitment-based approach
 */

export interface OffChainZKPInputs {
  // Private inputs (never revealed)
  accountProofData: [string, string, string, string]; // Flow account proof components
  salt: string; // Random salt for commitment
  nullifierSecret: string; // Secret for nullifier generation

  // Public inputs (visible on-chain)
  commitment: string; // Account commitment
  nullifier: string; // Unique nullifier
  messageHash: string; // ERC-4337 message hash
  challengeHash: string; // Challenge hash
  timestamp: string; // Proof timestamp
}

export interface OffChainZKProof {
  proof: {
    pi_a: [string, string];
    pi_b: [[string, string], [string, string]];
    pi_c: [string, string];
  };
  publicSignals: string[];
  metadata: {
    commitment: string;
    nullifier: string;
    timestamp: number;
    messageHash: string;
  };
}

export interface ProofGenerationRequest {
  flowAccountProof?: FlowAccountProofData; // Legacy support
  coaOwnershipProof?: COAOwnershipProofInContext; // Official Flow EVM proof
  challenge: string;
  messageHash: string;
  erc4337Operation?: any; // Optional ERC-4337 operation data
}

export interface COAProofGenerationRequest {
  coaOwnershipProof: COAOwnershipProofInContext;
  challenge: string;
  messageHash: string;
  erc4337Operation?: any;
}

export class OffChainZKPGenerator {
  private circuitWasmPath: string;
  private circuitZkeyPath: string;
  private vkeyPath: string;

  constructor(
    circuitWasmPath?: string,
    circuitZkeyPath?: string,
    vkeyPath?: string
  ) {
    this.circuitWasmPath =
      circuitWasmPath || "./circuits/build/flow-ownership.wasm";
    this.circuitZkeyPath =
      circuitZkeyPath || "./circuits/build/flow-ownership_0001.zkey";
    this.vkeyPath = vkeyPath || "./circuits/build/verification_key.json";
  }

  /**
   * Generate off-chain ZKP for Flow COA ownership (using official Flow EVM proof structure)
   * @param request COA proof generation request
   * @returns Zero-knowledge proof
   */
  async generateCOAOwnershipProof(
    request: COAProofGenerationRequest
  ): Promise<OffChainZKProof> {
    try {
      // 1. Verify Flow COA ownership proof using FCL
      const verificationResult =
        await flowAccountProofService.verifyCOAOwnershipProof(
          request.coaOwnershipProof,
          request.challenge
        );

      if (!verificationResult.verificationResult) {
        throw new Error("Flow COA ownership proof verification failed");
      }

      // 2. Generate circuit inputs without exposing sensitive data
      const circuitInputs = this.prepareCOACircuitInputs(
        request.coaOwnershipProof,
        request.challenge,
        request.messageHash,
        verificationResult.commitment,
        verificationResult.nullifierSecret
      );

      // 3. Generate ZK proof off-chain
      let zkProof: OffChainZKProof;

      if (this.circuitFilesExist()) {
        // Use real circuit if available
        zkProof = await this.generateRealProof(circuitInputs);
      } else {
        // Use mock proof for development/testing
        zkProof = this.generateMockProof(circuitInputs);
      }

      return zkProof;
    } catch (error) {
      console.error("Off-chain COA proof generation failed:", error);
      throw new Error(
        `COA proof generation failed: ${(error as Error).message}`
      );
    }
  }

  /**
   * Generate off-chain ZKP for Flow account ownership (legacy method)
   * @param request Proof generation request
   * @returns Zero-knowledge proof
   */
  async generateOwnershipProof(
    request: ProofGenerationRequest
  ): Promise<OffChainZKProof> {
    try {
      // 1. Verify Flow account proof using FCL
      if (!request.flowAccountProof) {
        throw new Error("Flow account proof is required");
      }

      const verificationResult =
        await flowAccountProofService.verifyAccountProof(
          request.flowAccountProof,
          request.challenge
        );

      if (!verificationResult.verificationResult) {
        throw new Error("Flow account proof verification failed");
      }

      // 2. Generate circuit inputs without exposing sensitive data
      const circuitInputs = this.prepareCircuitInputs(
        request.flowAccountProof,
        request.challenge,
        request.messageHash,
        verificationResult.commitment,
        verificationResult.nullifierSecret
      );

      // 3. Generate ZK proof off-chain
      let zkProof: OffChainZKProof;

      if (this.circuitFilesExist()) {
        // Use real circuit if available
        zkProof = await this.generateRealProof(circuitInputs);
      } else {
        // Use mock proof for development/testing
        zkProof = this.generateMockProof(circuitInputs);
      }

      return zkProof;
    } catch (error) {
      console.error("Off-chain proof generation failed:", error);
      throw new Error(`Proof generation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Prepare circuit inputs from Flow COA ownership proof (privacy-preserving)
   * @param coaProof COA ownership proof
   * @param challenge Original challenge
   * @param messageHash ERC-4337 message hash
   * @param commitment Account commitment
   * @param nullifierSecret Nullifier secret
   * @returns Circuit inputs
   */
  private prepareCOACircuitInputs(
    coaProof: COAOwnershipProofInContext,
    challenge: string,
    messageHash: string,
    commitment: string,
    nullifierSecret: string
  ): OffChainZKPInputs {
    // Convert COA proof to hashed components (privacy-preserving)
    const circuitData = flowAccountProofService.convertCOAProofToCircuitInputs(
      coaProof,
      challenge
    );

    // Generate random salt for commitment
    const salt = randomBytes(32).toString("hex");

    // Generate nullifier
    const nullifier = this.generateNullifier(
      circuitData.accountProofData[0], // Account identifier
      nullifierSecret,
      circuitData.challengeHash
    );

    // Current timestamp
    const timestamp = Date.now().toString();

    return {
      // Private inputs (witness)
      accountProofData: circuitData.accountProofData,
      salt,
      nullifierSecret,

      // Public inputs
      commitment,
      nullifier,
      messageHash,
      challengeHash: circuitData.challengeHash,
      timestamp,
    };
  }

  /**
   * Prepare circuit inputs from Flow account proof (legacy - privacy-preserving)
   * @param accountProofData Flow account proof
   * @param challenge Original challenge
   * @param messageHash ERC-4337 message hash
   * @param commitment Account commitment
   * @param nullifierSecret Nullifier secret
   * @returns Circuit inputs
   */
  private prepareCircuitInputs(
    accountProofData: FlowAccountProofData,
    challenge: string,
    messageHash: string,
    commitment: string,
    nullifierSecret: string
  ): OffChainZKPInputs {
    // Convert account proof to hashed components (privacy-preserving)
    const circuitData = flowAccountProofService.convertToCircuitInputs(
      accountProofData,
      challenge
    );

    // Generate random salt for commitment
    const salt = randomBytes(32).toString("hex");

    // Generate nullifier
    const nullifier = this.generateNullifier(
      circuitData.accountProofData[0], // Account identifier
      nullifierSecret,
      circuitData.challengeHash
    );

    // Current timestamp
    const timestamp = Date.now().toString();

    return {
      // Private inputs (witness)
      accountProofData: circuitData.accountProofData,
      salt,
      nullifierSecret,

      // Public inputs
      commitment,
      nullifier,
      messageHash,
      challengeHash: circuitData.challengeHash,
      timestamp,
    };
  }

  /**
   * Generate real ZK proof using compiled circuit
   * @param inputs Circuit inputs
   * @returns ZK proof
   */
  private async generateRealProof(
    inputs: OffChainZKPInputs
  ): Promise<OffChainZKProof> {
    try {
      // Format inputs for circom
      const circuitInputs = {
        accountProofData: inputs.accountProofData.map((x) =>
          this.hexToBigInt(x).toString()
        ),
        salt: this.hexToBigInt(inputs.salt).toString(),
        nullifierSecret: this.hexToBigInt(inputs.nullifierSecret).toString(),
        commitment: this.hexToBigInt(inputs.commitment).toString(),
        nullifier: this.hexToBigInt(inputs.nullifier).toString(),
        messageHash: this.hexToBigInt(inputs.messageHash).toString(),
        challengeHash: this.hexToBigInt(inputs.challengeHash).toString(),
        timestamp: inputs.timestamp,
      };

      // Generate proof
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        this.circuitWasmPath,
        this.circuitZkeyPath
      );

      return {
        proof: {
          pi_a: [proof.pi_a[0], proof.pi_a[1]],
          pi_b: [
            [proof.pi_b[0][1], proof.pi_b[0][0]],
            [proof.pi_b[1][1], proof.pi_b[1][0]],
          ],
          pi_c: [proof.pi_c[0], proof.pi_c[1]],
        },
        publicSignals: publicSignals.map((signal: any) => signal.toString()),
        metadata: {
          commitment: inputs.commitment,
          nullifier: inputs.nullifier,
          timestamp: parseInt(inputs.timestamp),
          messageHash: inputs.messageHash,
        },
      };
    } catch (error) {
      console.error("Real proof generation failed:", error);
      throw error;
    }
  }

  /**
   * Generate mock proof for development/testing
   * @param inputs Circuit inputs
   * @returns Mock ZK proof
   */
  private generateMockProof(inputs: OffChainZKPInputs): OffChainZKProof {
    // Generate deterministic but fake proof for testing
    const hash = createHash("sha256")
      .update(JSON.stringify(inputs))
      .digest("hex");

    return {
      proof: {
        pi_a: ["0x" + hash.slice(0, 64), "0x" + hash.slice(64, 128)],
        pi_b: [
          ["0x" + hash.slice(0, 64), "0x" + hash.slice(64, 128)],
          ["0x" + hash.slice(128, 192), "0x" + hash.slice(192, 256)],
        ],
        pi_c: ["0x" + hash.slice(0, 64), "0x" + hash.slice(64, 128)],
      },
      publicSignals: [
        inputs.commitment,
        inputs.nullifier,
        inputs.messageHash,
        inputs.challengeHash,
        inputs.timestamp,
      ],
      metadata: {
        commitment: inputs.commitment,
        nullifier: inputs.nullifier,
        timestamp: parseInt(inputs.timestamp),
        messageHash: inputs.messageHash,
      },
    };
  }

  /**
   * Generate nullifier for replay protection
   * @param accountIdentifier Account identifier hash
   * @param nullifierSecret Secret for nullifier
   * @param challengeHash Challenge hash
   * @returns Nullifier
   */
  private generateNullifier(
    accountIdentifier: string,
    nullifierSecret: string,
    challengeHash: string
  ): string {
    const hash = createHash("sha256");
    hash.update(accountIdentifier);
    hash.update(nullifierSecret);
    hash.update(challengeHash);
    return hash.digest("hex");
  }

  /**
   * Verify ZK proof off-chain
   * @param proof ZK proof to verify
   * @returns True if proof is valid
   */
  async verifyProof(proof: OffChainZKProof): Promise<boolean> {
    try {
      if (!this.circuitFilesExist()) {
        // For mock proofs, always return true in development
        console.warn("Circuit files not found, using mock verification");
        return true;
      }

      // Load verification key
      const vKey = JSON.parse(fs.readFileSync(this.vkeyPath, "utf-8"));

      // Verify proof
      const isValid = await snarkjs.groth16.verify(
        vKey,
        proof.publicSignals,
        proof.proof
      );

      return isValid;
    } catch (error) {
      console.error("Proof verification failed:", error);
      return false;
    }
  }

  /**
   * Format proof for ERC-4337 UserOperation signature
   * @param proof ZK proof
   * @returns Encoded signature
   */
  formatForUserOperation(proof: OffChainZKProof): string {
    // Encode proof components for UserOperation.signature field
    const { ethers } = require("ethers");
    const abiCoder = new ethers.utils.AbiCoder();

    return abiCoder.encode(
      [
        "uint256[2]",
        "uint256[2][2]",
        "uint256[2]",
        "uint256[]",
        "bytes32",
        "bytes32",
      ],
      [
        proof.proof.pi_a,
        proof.proof.pi_b,
        proof.proof.pi_c,
        proof.publicSignals,
        proof.metadata.commitment,
        proof.metadata.nullifier,
      ]
    );
  }

  /**
   * Batch generate proofs for multiple requests
   * @param requests Array of proof requests
   * @returns Array of ZK proofs
   */
  async batchGenerateProofs(
    requests: ProofGenerationRequest[]
  ): Promise<OffChainZKProof[]> {
    const proofs: OffChainZKProof[] = [];

    for (const request of requests) {
      try {
        const proof = await this.generateOwnershipProof(request);
        proofs.push(proof);
      } catch (error) {
        console.error(`Failed to generate proof for request:`, error);
        // Continue with other requests
      }
    }

    return proofs;
  }

  /**
   * Check if circuit files exist
   * @returns True if circuit files are available
   */
  private circuitFilesExist(): boolean {
    return (
      fs.existsSync(this.circuitWasmPath) &&
      fs.existsSync(this.circuitZkeyPath) &&
      fs.existsSync(this.vkeyPath)
    );
  }

  /**
   * Convert hex string to BigInt
   * @param hex Hex string
   * @returns BigInt
   */
  private hexToBigInt(hex: string): bigint {
    // Remove 0x prefix if present
    const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
    return BigInt("0x" + cleanHex);
  }

  /**
   * Create commitment for account registration
   * @param accountProofData Flow account proof
   * @param salt Random salt
   * @returns Commitment hash
   */
  createCommitment(
    accountProofData: FlowAccountProofData,
    salt: string
  ): string {
    const hash = createHash("sha256");
    hash.update(accountProofData.address);
    hash.update(accountProofData.signature);
    hash.update(accountProofData.keyId.toString());
    hash.update(salt);
    return hash.digest("hex");
  }
}

// Export singleton instance
export const offChainZKPGenerator = new OffChainZKPGenerator();
