import * as fcl from "@onflow/fcl";
import { createHash, randomBytes } from "crypto";

/**
 * Flow Account Proof Integration
 * Uses Flow's built-in account-proof service for off-chain ownership verification
 * NO PUBLIC KEY EXPOSURE - only proof of ownership
 */

// Configure Flow for testnet
fcl.config({
  "accessNode.api": "https://rest-testnet.onflow.org",
  "discovery.wallet": "https://fcl-discovery.onflow.org/testnet/authn",
  "0xProfile": "0xba1132bc08f82fe2"
});

export interface FlowAccountProofData {
  address: string;
  keyId: number;
  signature: string;
  nonce: string;
  timestamp: number;
}

export interface FlowAccountProofResponse {
  accountProofData: FlowAccountProofData;
  verificationResult: boolean;
  commitment: string;
  nullifierSecret: string;
}

export interface ChallengeData {
  challenge: string;
  timestamp: number;
  expires: number;
}

export class FlowAccountProofService {
  private activeChallenges: Map<string, ChallengeData> = new Map();
  private readonly CHALLENGE_EXPIRY = 300000; // 5 minutes

  /**
   * Generate a cryptographic challenge for Flow account proof
   * @returns Challenge data
   */
  generateChallenge(): ChallengeData {
    const challenge = randomBytes(32).toString('hex');
    const timestamp = Date.now();
    const expires = timestamp + this.CHALLENGE_EXPIRY;
    
    const challengeData: ChallengeData = {
      challenge,
      timestamp,
      expires
    };
    
    this.activeChallenges.set(challenge, challengeData);
    
    // Clean up expired challenges
    this.cleanupExpiredChallenges();
    
    return challengeData;
  }

  /**
   * Request Flow account proof from user's wallet
   * @param challenge Challenge string
   * @returns Account proof data or null if failed
   */
  async requestAccountProof(challenge: string): Promise<FlowAccountProofData | null> {
    try {
      // Verify challenge is valid and not expired
      const challengeData = this.activeChallenges.get(challenge);
      if (!challengeData || Date.now() > challengeData.expires) {
        throw new Error('Invalid or expired challenge');
      }

      // Create message for signing
      const message = this.createProofMessage(challenge, challengeData.timestamp);
      
      // Request signature from Flow wallet using FCL
      const signatureResponse = await fcl.currentUser.signUserMessage(message);
      
      if (!signatureResponse || signatureResponse.length === 0) {
        return null;
      }

      // Extract account proof data
      const accountProofData: FlowAccountProofData = {
        address: signatureResponse[0].addr,
        keyId: signatureResponse[0].keyId,
        signature: signatureResponse[0].signature,
        nonce: challenge,
        timestamp: challengeData.timestamp
      };

      return accountProofData;
    } catch (error) {
      console.error('Failed to request account proof:', error);
      return null;
    }
  }

  /**
   * Verify Flow account proof using FCL
   * @param accountProofData Account proof data to verify
   * @param challenge Original challenge
   * @returns Verification result with commitment data
   */
  async verifyAccountProof(
    accountProofData: FlowAccountProofData, 
    challenge: string
  ): Promise<FlowAccountProofResponse> {
    try {
      // Verify challenge exists and is valid
      const challengeData = this.activeChallenges.get(challenge);
      if (!challengeData) {
        throw new Error('Invalid challenge');
      }

      // Recreate the original message
      const message = this.createProofMessage(challenge, challengeData.timestamp);
      
      // Verify signature using FCL account proof verification
      const verificationData = {
        address: accountProofData.address,
        signature: accountProofData.signature,
        keyId: accountProofData.keyId,
        message: message
      };

      // Use FCL's built-in verification (this connects to Flow blockchain)
      const isValid = await this.verifySignatureWithFlow(verificationData);
      
      if (!isValid) {
        return {
          accountProofData,
          verificationResult: false,
          commitment: '',
          nullifierSecret: ''
        };
      }

      // Generate commitment and nullifier secret for privacy
      const { commitment, nullifierSecret } = this.generateCommitmentData(
        accountProofData,
        challenge
      );

      // Clean up used challenge
      this.activeChallenges.delete(challenge);

      return {
        accountProofData,
        verificationResult: true,
        commitment,
        nullifierSecret
      };

    } catch (error) {
      console.error('Account proof verification failed:', error);
      return {
        accountProofData,
        verificationResult: false,
        commitment: '',
        nullifierSecret: ''
      };
    }
  }

  /**
   * Generate commitment data for privacy-preserving proofs
   * @param accountProofData Verified account proof
   * @param challenge Original challenge
   * @returns Commitment and nullifier secret
   */
  private generateCommitmentData(
    accountProofData: FlowAccountProofData,
    challenge: string
  ): { commitment: string; nullifierSecret: string } {
    // Generate random salt for commitment
    const salt = randomBytes(32);
    
    // Generate nullifier secret
    const nullifierSecret = randomBytes(32).toString('hex');
    
    // Create commitment: Hash(accountData, salt)
    // This hides the account identity while proving ownership
    const commitmentHash = createHash('sha256');
    commitmentHash.update(accountProofData.address);
    commitmentHash.update(accountProofData.signature);
    commitmentHash.update(accountProofData.keyId.toString());
    commitmentHash.update(salt);
    
    const commitment = commitmentHash.digest('hex');
    
    return { commitment, nullifierSecret };
  }

  /**
   * Create message for Flow account proof signing
   * @param challenge Challenge string
   * @param timestamp Challenge timestamp
   * @returns Message to be signed
   */
  private createProofMessage(challenge: string, timestamp: number): string {
    return `Flow Account Ownership Proof\nChallenge: ${challenge}\nTimestamp: ${timestamp}\nDo not sign this message unless you trust the requesting application.`;
  }

  /**
   * Verify signature with Flow blockchain using FCL
   * @param verificationData Data to verify
   * @returns True if signature is valid
   */
  private async verifySignatureWithFlow(verificationData: {
    address: string;
    signature: string;
    keyId: number;
    message: string;
  }): Promise<boolean> {
    try {
      // Use FCL's signature verification
      // This makes a call to Flow blockchain to verify the signature
      const isValid = await fcl.verifyUserSignatures(
        verificationData.message,
        [{
          addr: verificationData.address,
          keyId: verificationData.keyId,
          signature: verificationData.signature
        }]
      );
      
      return isValid;
    } catch (error) {
      console.error('Flow signature verification failed:', error);
      return false;
    }
  }

  /**
   * Clean up expired challenges
   */
  private cleanupExpiredChallenges(): void {
    const now = Date.now();
    for (const [challenge, data] of this.activeChallenges.entries()) {
      if (now > data.expires) {
        this.activeChallenges.delete(challenge);
      }
    }
  }

  /**
   * Get current user from FCL
   * @returns Current user data or null
   */
  async getCurrentUser(): Promise<{ addr: string; loggedIn: boolean } | null> {
    try {
      const user = await fcl.currentUser.snapshot();
      return user;
    } catch (error) {
      console.error('Failed to get current user:', error);
      return null;
    }
  }

  /**
   * Authenticate user with Flow wallet
   * @returns Authentication result
   */
  async authenticate(): Promise<boolean> {
    try {
      await fcl.authenticate();
      const user = await this.getCurrentUser();
      return user?.loggedIn || false;
    } catch (error) {
      console.error('Authentication failed:', error);
      return false;
    }
  }

  /**
   * Unauthenticate user
   */
  async unauthenticate(): Promise<void> {
    await fcl.unauthenticate();
  }

  /**
   * Convert account proof data to circuit inputs (without exposing sensitive data)
   * @param accountProofData Verified account proof
   * @param challenge Original challenge
   * @returns Circuit inputs for ZKP generation
   */
  convertToCircuitInputs(
    accountProofData: FlowAccountProofData,
    challenge: string
  ): {
    accountProofData: [string, string, string, string];
    challengeHash: string;
  } {
    // Convert account data to circuit-compatible format
    // Hash components to hide actual values
    const hash1 = createHash('sha256').update(accountProofData.address).digest('hex');
    const hash2 = createHash('sha256').update(accountProofData.signature).digest('hex');
    const hash3 = createHash('sha256').update(accountProofData.keyId.toString()).digest('hex');
    const hash4 = createHash('sha256').update(accountProofData.timestamp.toString()).digest('hex');
    
    const challengeHash = createHash('sha256').update(challenge).digest('hex');
    
    return {
      accountProofData: [hash1, hash2, hash3, hash4],
      challengeHash
    };
  }
}

// Export singleton instance
export const flowAccountProofService = new FlowAccountProofService();