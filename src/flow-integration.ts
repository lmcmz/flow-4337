import * as fcl from "@onflow/fcl";
import { ec as EC } from "elliptic";
import { createHash } from "crypto";
import { Buffer } from "buffer";

/**
 * Flow Integration SDK
 * Handles Flow account operations and signature generation for ZKP
 */

// Flow configuration
fcl.config({
  "accessNode.api": "https://rest-testnet.onflow.org",
  "discovery.wallet": "https://fcl-discovery.onflow.org/testnet/authn",
  "0xProfile": "0xba1132bc08f82fe2",
});

export interface FlowAccount {
  address: string;
  publicKey: string;
  privateKey?: string;
  keyIndex: number;
  sequenceNumber: number;
}

export interface FlowSignature {
  signature: string;
  keyId: number;
  addr: string;
}

export interface ZKPInputs {
  messageHash: string;
  publicKeyX: string;
  publicKeyY: string;
  accountAddress: string;
  nonce: string;
  signature: [string, string];
  privateKey: string;
}

export class FlowIntegration {
  private ec: EC;

  constructor() {
    this.ec = new EC("p256");
  }

  /**
   * Create a new Flow account for testing
   * @returns Promise<FlowAccount>
   */
  async createFlowAccount(): Promise<FlowAccount> {
    // Generate key pair using P-256 curve (Flow's native curve)
    const keyPair = this.ec.genKeyPair();
    const privateKey = keyPair.getPrivate("hex");
    const publicKey = keyPair.getPublic("hex");

    // Derive Flow address from public key
    const address = this.deriveFlowAddress(publicKey);

    return {
      address,
      publicKey,
      privateKey,
      keyIndex: 0,
      sequenceNumber: 0,
    };
  }

  /**
   * Derive Flow address from public key
   * @param publicKey Public key in hex format
   * @returns Flow address
   */
  private deriveFlowAddress(publicKey: string): string {
    // Remove '04' prefix if present (uncompressed format indicator)
    const cleanKey = publicKey.startsWith("04")
      ? publicKey.slice(2)
      : publicKey;

    // Flow address derivation: hash(publicKey + keyIndex + hashAlgo + weight)
    const keyIndex = Buffer.from([0, 0, 0, 0]); // keyIndex 0
    const hashAlgo = Buffer.from([0x03]); // SHA3-256
    const weight = Buffer.from([0x03, 0xe8]); // weight 1000

    const hash = createHash("sha3-256");
    hash.update(Buffer.from(cleanKey, "hex"));
    hash.update(keyIndex);
    hash.update(hashAlgo);
    hash.update(weight);

    const addressBytes = hash.digest();
    // Take last 8 bytes for Flow address
    const address = "0x" + addressBytes.slice(-8).toString("hex");

    return address;
  }

  /**
   * Sign a message with Flow account
   * @param message Message to sign
   * @param account Flow account
   * @returns Promise<FlowSignature>
   */
  async signMessage(
    message: string,
    account: FlowAccount
  ): Promise<FlowSignature> {
    if (!account.privateKey) {
      throw new Error("Private key required for signing");
    }

    // Create message hash
    const messageHash = createHash("sha256").update(message).digest();

    // Sign with ECDSA P-256
    const keyPair = this.ec.keyFromPrivate(account.privateKey, "hex");
    const signature = keyPair.sign(messageHash);

    // Format signature as hex string
    const r = signature.r.toString("hex").padStart(64, "0");
    const s = signature.s.toString("hex").padStart(64, "0");
    const signatureHex = r + s;

    return {
      signature: signatureHex,
      keyId: account.keyIndex,
      addr: account.address,
    };
  }

  /**
   * Prepare ZKP inputs from Flow account and message
   * @param message Message to sign
   * @param account Flow account
   * @param nonce Unique nonce for replay protection
   * @returns ZKPInputs
   */
  async prepareZKPInputs(
    message: string,
    account: FlowAccount,
    nonce: number
  ): Promise<ZKPInputs> {
    if (!account.privateKey) {
      throw new Error("Private key required for ZKP generation");
    }

    // Sign the message
    const flowSignature = await this.signMessage(message, account);

    // Extract public key coordinates
    const keyPair = this.ec.keyFromPrivate(account.privateKey, "hex");
    const publicKeyPoint = keyPair.getPublic();
    const publicKeyX = publicKeyPoint.getX().toString("hex").padStart(64, "0");
    const publicKeyY = publicKeyPoint.getY().toString("hex").padStart(64, "0");

    // Create message hash
    const messageHash = createHash("sha256").update(message).digest("hex");

    // Convert Flow address to numeric format for circuit
    const addressNumeric = this.flowAddressToNumeric(account.address);

    // Extract signature components
    const r = flowSignature.signature.slice(0, 64);
    const s = flowSignature.signature.slice(64, 128);

    return {
      messageHash: "0x" + messageHash,
      publicKeyX: "0x" + publicKeyX,
      publicKeyY: "0x" + publicKeyY,
      accountAddress: addressNumeric,
      nonce: nonce.toString(),
      signature: ["0x" + r, "0x" + s],
      privateKey: "0x" + account.privateKey,
    };
  }

  /**
   * Convert Flow address to numeric format
   * @param address Flow address
   * @returns Numeric representation
   */
  private flowAddressToNumeric(address: string): string {
    // Remove '0x' prefix and convert to decimal
    const cleanAddress = address.replace("0x", "");
    return "0x" + cleanAddress.padStart(64, "0");
  }

  /**
   * Get Flow account info from wallet
   * @returns Promise<FlowAccount | null>
   */
  async getCurrentUser(): Promise<FlowAccount | null> {
    try {
      const user = await fcl.currentUser.snapshot();

      if (!user.loggedIn || !user.addr) {
        return null;
      }

      // Get account info
      const account = await fcl.account(user.addr);

      return {
        address: user.addr,
        publicKey: account.keys[0].publicKey,
        keyIndex: (account.keys[0] as any).keyIndex || 0,
        sequenceNumber: account.keys[0].sequenceNumber,
      };
    } catch (error) {
      console.error("Error getting current user:", error);
      return null;
    }
  }

  /**
   * Authenticate with Flow wallet
   * @returns Promise<FlowAccount | null>
   */
  async authenticate(): Promise<FlowAccount | null> {
    try {
      await fcl.authenticate();
      return await this.getCurrentUser();
    } catch (error) {
      console.error("Authentication failed:", error);
      return null;
    }
  }

  /**
   * Unauthenticate from Flow wallet
   */
  async unauthenticate(): Promise<void> {
    await fcl.unauthenticate();
  }

  /**
   * Verify a Flow signature
   * @param message Original message
   * @param signature Signature to verify
   * @param publicKey Public key to verify against
   * @returns boolean
   */
  verifySignature(
    message: string,
    signature: string,
    publicKey: string
  ): boolean {
    try {
      const messageHash = createHash("sha256").update(message).digest();

      // Extract signature components
      const r = signature.slice(0, 64);
      const s = signature.slice(64, 128);

      // Verify signature
      const keyPair = this.ec.keyFromPublic(publicKey, "hex");
      return keyPair.verify(messageHash, { r, s });
    } catch (error) {
      console.error("Signature verification failed:", error);
      return false;
    }
  }

  /**
   * Get Flow account details for ZKP
   * @param account Flow account
   * @returns Account details formatted for ZKP
   */
  getAccountDetailsForZKP(account: FlowAccount) {
    if (!account.privateKey) {
      throw new Error("Private key required");
    }

    const keyPair = this.ec.keyFromPrivate(account.privateKey, "hex");
    const publicKeyPoint = keyPair.getPublic();

    return {
      address: this.flowAddressToNumeric(account.address),
      publicKeyX:
        "0x" + publicKeyPoint.getX().toString("hex").padStart(64, "0"),
      publicKeyY:
        "0x" + publicKeyPoint.getY().toString("hex").padStart(64, "0"),
      privateKey: "0x" + account.privateKey,
    };
  }
}

// Export singleton instance
export const flowIntegration = new FlowIntegration();
