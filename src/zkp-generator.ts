import * as snarkjs from "snarkjs";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";

/**
 * ZKP Generator for Flow Account Signatures
 * Handles zero-knowledge proof generation and verification
 */

export interface ZKProof {
  proof: {
    pi_a: [string, string];
    pi_b: [[string, string], [string, string]];
    pi_c: [string, string];
  };
  publicSignals: string[];
}

export interface CircuitInputs {
  messageHash: string;
  publicKeyX: string;
  publicKeyY: string;
  accountAddress: string;
  nonce: string;
  signature: [string, string];
  privateKey: string;
}

export interface ProofComponents {
  proof_a: [string, string];
  proof_b: [[string, string], [string, string]];
  proof_c: [string, string];
  publicInputs: string[];
}

export class ZKPGenerator {
  private circuitWasmPath: string;
  private circuitZkeyPath: string;
  private vkeyPath: string;

  constructor(
    circuitWasmPath?: string,
    circuitZkeyPath?: string,
    vkeyPath?: string
  ) {
    this.circuitWasmPath = circuitWasmPath || "./circuits/build/flow-signature.wasm";
    this.circuitZkeyPath = circuitZkeyPath || "./circuits/build/flow-signature_0001.zkey";
    this.vkeyPath = vkeyPath || "./circuits/build/verification_key.json";
  }

  /**
   * Generate zero-knowledge proof for Flow signature
   * @param inputs Circuit inputs
   * @returns Promise<ZKProof>
   */
  async generateProof(inputs: CircuitInputs): Promise<ZKProof> {
    try {
      // Validate inputs
      this.validateInputs(inputs);

      // Convert inputs to proper format for circom
      const circuitInputs = this.formatInputsForCircuit(inputs);

      // Generate witness
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        this.circuitWasmPath,
        this.circuitZkeyPath
      );

      return {
        proof: {
          pi_a: [proof.pi_a[0], proof.pi_a[1]],
          pi_b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
          pi_c: [proof.pi_c[0], proof.pi_c[1]]
        },
        publicSignals: publicSignals.map(signal => signal.toString())
      };
    } catch (error) {
      console.error("Error generating proof:", error);
      throw new Error(`Proof generation failed: ${error.message}`);
    }
  }

  /**
   * Verify zero-knowledge proof
   * @param proof The proof to verify
   * @param publicSignals Public signals
   * @returns Promise<boolean>
   */
  async verifyProof(proof: ZKProof["proof"], publicSignals: string[]): Promise<boolean> {
    try {
      // Load verification key
      const vKey = JSON.parse(fs.readFileSync(this.vkeyPath, "utf-8"));

      // Verify proof
      const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
      return res;
    } catch (error) {
      console.error("Error verifying proof:", error);
      return false;
    }
  }

  /**
   * Format proof for smart contract consumption
   * @param zkProof Generated ZK proof
   * @returns ProofComponents formatted for Solidity
   */
  formatProofForContract(zkProof: ZKProof): ProofComponents {
    return {
      proof_a: [
        zkProof.proof.pi_a[0],
        zkProof.proof.pi_a[1]
      ],
      proof_b: [
        [zkProof.proof.pi_b[0][0], zkProof.proof.pi_b[0][1]],
        [zkProof.proof.pi_b[1][0], zkProof.proof.pi_b[1][1]]
      ],
      proof_c: [
        zkProof.proof.pi_c[0],
        zkProof.proof.pi_c[1]
      ],
      publicInputs: zkProof.publicSignals
    };
  }

  /**
   * Generate mock proof for testing (when circuits are not compiled)
   * @param inputs Circuit inputs
   * @returns Mock proof for testing
   */
  generateMockProof(inputs: CircuitInputs): ProofComponents {
    // Generate deterministic but fake proof components for testing
    const hash = createHash('sha256').update(JSON.stringify(inputs)).digest('hex');
    
    return {
      proof_a: [
        '0x' + hash.slice(0, 64),
        '0x' + hash.slice(64, 128)
      ],
      proof_b: [
        ['0x' + hash.slice(0, 64), '0x' + hash.slice(64, 128)],
        ['0x' + hash.slice(128, 192), '0x' + hash.slice(192, 256)]
      ],
      proof_c: [
        '0x' + hash.slice(0, 64),
        '0x' + hash.slice(64, 128)
      ],
      publicInputs: [
        this.hexToBigInt(inputs.messageHash).toString(),
        this.hexToBigInt(inputs.publicKeyX).toString(),
        this.hexToBigInt(inputs.publicKeyY).toString(),
        this.hexToBigInt(inputs.accountAddress).toString(),
        inputs.nonce
      ]
    };
  }

  /**
   * Validate circuit inputs
   * @param inputs Inputs to validate
   */
  private validateInputs(inputs: CircuitInputs): void {
    if (!inputs.messageHash || !inputs.messageHash.startsWith('0x')) {
      throw new Error('Invalid messageHash format');
    }
    if (!inputs.publicKeyX || !inputs.publicKeyX.startsWith('0x')) {
      throw new Error('Invalid publicKeyX format');
    }
    if (!inputs.publicKeyY || !inputs.publicKeyY.startsWith('0x')) {
      throw new Error('Invalid publicKeyY format');
    }
    if (!inputs.accountAddress || !inputs.accountAddress.startsWith('0x')) {
      throw new Error('Invalid accountAddress format');
    }
    if (!inputs.nonce || isNaN(Number(inputs.nonce))) {
      throw new Error('Invalid nonce format');
    }
    if (!Array.isArray(inputs.signature) || inputs.signature.length !== 2) {
      throw new Error('Invalid signature format');
    }
    if (!inputs.privateKey || !inputs.privateKey.startsWith('0x')) {
      throw new Error('Invalid privateKey format');
    }
  }

  /**
   * Format inputs for circom circuit
   * @param inputs Raw inputs
   * @returns Formatted inputs for circuit
   */
  private formatInputsForCircuit(inputs: CircuitInputs): any {
    return {
      messageHash: this.hexToBigInt(inputs.messageHash).toString(),
      publicKeyX: this.hexToBigInt(inputs.publicKeyX).toString(),
      publicKeyY: this.hexToBigInt(inputs.publicKeyY).toString(),
      accountAddress: this.hexToBigInt(inputs.accountAddress).toString(),
      nonce: inputs.nonce,
      signature: [
        this.hexToBigInt(inputs.signature[0]).toString(),
        this.hexToBigInt(inputs.signature[1]).toString()
      ],
      privateKey: this.hexToBigInt(inputs.privateKey).toString()
    };
  }

  /**
   * Convert hex string to BigInt
   * @param hex Hex string
   * @returns BigInt
   */
  private hexToBigInt(hex: string): bigint {
    return BigInt(hex);
  }

  /**
   * Generate trusted setup for circuit (development only)
   * @param circuitPath Path to compiled circuit
   * @param ptauPath Path to powers of tau file
   * @returns Promise<void>
   */
  async generateTrustedSetup(circuitPath: string, ptauPath: string): Promise<void> {
    try {
      console.log("Generating trusted setup...");
      
      // Generate zkey file
      await snarkjs.groth16.setup(circuitPath, ptauPath, this.circuitZkeyPath);
      
      // Export verification key
      const vKey = await snarkjs.zKey.exportVerificationKey(this.circuitZkeyPath);
      fs.writeFileSync(this.vkeyPath, JSON.stringify(vKey, null, 2));
      
      console.log("Trusted setup generated successfully");
    } catch (error) {
      console.error("Error generating trusted setup:", error);
      throw error;
    }
  }

  /**
   * Export Solidity verifier contract
   * @param outputPath Path to output Solidity file
   * @returns Promise<void>
   */
  async exportSolidityVerifier(outputPath: string): Promise<void> {
    try {
      const solidityCode = await snarkjs.zKey.exportSolidityVerifier(this.circuitZkeyPath);
      fs.writeFileSync(outputPath, solidityCode);
      console.log(`Solidity verifier exported to ${outputPath}`);
    } catch (error) {
      console.error("Error exporting Solidity verifier:", error);
      throw error;
    }
  }

  /**
   * Check if circuit files exist
   * @returns boolean
   */
  circuitFilesExist(): boolean {
    return fs.existsSync(this.circuitWasmPath) && 
           fs.existsSync(this.circuitZkeyPath) && 
           fs.existsSync(this.vkeyPath);
  }

  /**
   * Batch generate proofs for multiple inputs
   * @param inputsArray Array of circuit inputs
   * @returns Promise<ZKProof[]>
   */
  async batchGenerateProofs(inputsArray: CircuitInputs[]): Promise<ZKProof[]> {
    const proofs: ZKProof[] = [];
    
    for (const inputs of inputsArray) {
      const proof = await this.generateProof(inputs);
      proofs.push(proof);
    }
    
    return proofs;
  }

  /**
   * Create user operation signature from ZK proof
   * @param proof ZK proof components
   * @returns Encoded signature for UserOperation
   */
  createUserOperationSignature(proof: ProofComponents): string {
    // Encode proof components for UserOperation.signature field
    const abiCoder = new (require('ethers').utils.AbiCoder)();
    
    return abiCoder.encode(
      ['uint256[2]', 'uint256[2][2]', 'uint256[2]', 'uint256[]'],
      [
        proof.proof_a,
        proof.proof_b,
        proof.proof_c,
        proof.publicInputs
      ]
    );
  }
}

// Export singleton instance
export const zkpGenerator = new ZKPGenerator();