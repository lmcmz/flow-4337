import express from "express";
import cors from "cors";
import { createHash } from "crypto";
import {
  flowAccountProofService,
  FlowAccountProofData,
  COAOwnershipProofInContext,
} from "./flow-account-proof";
import {
  offChainZKPGenerator,
  OffChainZKProof,
  ProofGenerationRequest,
  COAProofGenerationRequest,
} from "./off-chain-zkp";

/**
 * Off-Chain Proof Generation Service
 * RESTful API for generating privacy-preserving Flow account ownership proofs
 * NO PUBLIC KEY EXPOSURE - Uses Flow's account-proof service + ZKP
 */

export interface ProofServiceConfig {
  port: number;
  corsOrigin: string[];
  rateLimit: {
    windowMs: number;
    max: number;
  };
}

export interface ChallengeResponse {
  challenge: string;
  expires: number;
  message: string;
}

export interface ProofResponse {
  success: boolean;
  proof?: OffChainZKProof;
  userOpSignature?: string;
  commitment?: string;
  nullifier?: string;
  error?: string;
}

export interface AccountRegistrationRequest {
  flowAccountProof?: FlowAccountProofData; // Legacy support
  coaOwnershipProof?: COAOwnershipProofInContext; // Official Flow EVM proof
  challenge: string;
  erc4337AccountAddress: string;
}

export interface COARegistrationRequest {
  coaOwnershipProof: COAOwnershipProofInContext;
  challenge: string;
  erc4337AccountAddress: string;
}

export interface AccountRegistrationResponse {
  success: boolean;
  commitment?: string;
  accountAddress?: string;
  error?: string;
}

export class OffChainProofService {
  private app: express.Application;
  private config: ProofServiceConfig;
  private isRunning: boolean = false;

  // Service statistics
  private stats = {
    totalChallengesGenerated: 0,
    totalProofsGenerated: 0,
    totalProofFailures: 0,
    totalAccountsRegistered: 0,
  };

  constructor(config?: Partial<ProofServiceConfig>) {
    this.config = {
      port: 3001,
      corsOrigin: ["http://localhost:3000", "http://localhost:3001"],
      rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
      },
      ...config,
    };

    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup Express middleware
   */
  private setupMiddleware(): void {
    // CORS
    this.app.use(
      cors({
        origin: this.config.corsOrigin,
        credentials: true,
      })
    );

    // JSON parsing
    this.app.use(express.json({ limit: "10mb" }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging
    this.app.use((req, res, next) => {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] ${req.method} ${req.path} - ${req.ip}`);
      next();
    });

    // Error handling
    this.app.use(
      (
        error: any,
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
      ) => {
        console.error("Unhandled error:", error);
        res.status(500).json({
          success: false,
          error: "Internal server error",
        });
      }
    );
  }

  /**
   * Setup API routes
   */
  private setupRoutes(): void {
    // Health check
    this.app.get("/health", (req, res) => {
      res.json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        stats: this.stats,
      });
    });

    // Generate challenge for Flow account proof
    this.app.post("/api/challenge", (req, res) => {
      this.handleGenerateChallenge(req, res);
    });

    // Generate off-chain ZK proof (supports both legacy and COA proofs)
    this.app.post("/api/proof/generate", (req, res) => {
      this.handleGenerateProof(req, res);
    });

    // Generate off-chain ZK proof using official COA ownership proof
    this.app.post("/api/proof/generate-coa", (req, res) => {
      this.handleGenerateCOAProof(req, res);
    });

    // Verify ZK proof
    this.app.post("/api/proof/verify", (req, res) => {
      this.handleVerifyProof(req, res);
    });

    // Register Flow account commitment (legacy + COA support)
    this.app.post("/api/account/register", (req, res) => {
      this.handleAccountRegistration(req, res);
    });

    // Register COA ownership proof commitment
    this.app.post("/api/account/register-coa", (req, res) => {
      this.handleCOARegistration(req, res);
    });

    // Batch generate proofs
    this.app.post("/api/proof/batch", (req, res) => {
      this.handleBatchGenerateProofs(req, res);
    });

    // Get service statistics
    this.app.get("/api/stats", (req, res) => {
      res.json({
        success: true,
        stats: this.stats,
        timestamp: new Date().toISOString(),
      });
    });

    // Documentation endpoint
    this.app.get("/api/docs", (req, res) => {
      res.json({
        title: "Flow ZKP Off-Chain Proof Service API",
        version: "1.0.0",
        description:
          "Privacy-preserving Flow account ownership proof generation",
        endpoints: {
          "POST /api/challenge": "Generate challenge for Flow account proof",
          "POST /api/proof/generate":
            "Generate off-chain ZK proof (auto-detects legacy/COA)",
          "POST /api/proof/generate-coa":
            "Generate ZK proof using official Flow EVM COA structure",
          "POST /api/proof/verify": "Verify ZK proof",
          "POST /api/account/register":
            "Register account commitment (auto-detects legacy/COA)",
          "POST /api/account/register-coa":
            "Register COA ownership proof commitment",
          "POST /api/proof/batch": "Batch generate proofs",
          "GET /api/stats": "Get service statistics",
          "GET /health": "Health check",
        },
        supportedProofTypes: {
          "Legacy Flow Account Proof":
            "flowAccountProof field (backward compatibility)",
          "Official Flow EVM COA Proof":
            "coaOwnershipProof field (recommended)",
        },
      });
    });
  }

  /**
   * Handle challenge generation
   */
  private async handleGenerateChallenge(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const challengeData = flowAccountProofService.generateChallenge();
      this.stats.totalChallengesGenerated++;

      const response: ChallengeResponse = {
        challenge: challengeData.challenge,
        expires: challengeData.expires,
        message: `Please sign this challenge to prove Flow account ownership: ${challengeData.challenge}`,
      };

      res.json({
        success: true,
        ...response,
      });
    } catch (error) {
      console.error("Challenge generation failed:", error);
      res.status(500).json({
        success: false,
        error: "Failed to generate challenge",
      });
    }
  }

  /**
   * Handle COA ZK proof generation (official Flow EVM proof structure)
   */
  private async handleGenerateCOAProof(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const {
        coaOwnershipProof,
        challenge,
        messageHash,
        erc4337Operation,
      }: COAProofGenerationRequest = req.body;

      // Validate input
      if (!coaOwnershipProof || !challenge || !messageHash) {
        res.status(400).json({
          success: false,
          error:
            "Missing required fields: coaOwnershipProof, challenge, messageHash",
        });
        return;
      }

      // Generate off-chain ZK proof using official COA structure
      const proof = await offChainZKPGenerator.generateCOAOwnershipProof({
        coaOwnershipProof,
        challenge,
        messageHash,
        erc4337Operation,
      });

      // Format for UserOperation
      const userOpSignature =
        offChainZKPGenerator.formatForUserOperation(proof);

      this.stats.totalProofsGenerated++;

      const response: ProofResponse = {
        success: true,
        proof,
        userOpSignature,
        commitment: proof.metadata.commitment,
        nullifier: proof.metadata.nullifier,
      };

      res.json(response);
    } catch (error) {
      console.error("COA proof generation failed:", error);
      this.stats.totalProofFailures++;

      res.status(500).json({
        success: false,
        error: `COA proof generation failed: ${(error as Error).message}`,
      });
    }
  }

  /**
   * Handle ZK proof generation (legacy method with auto-detection)
   */
  private async handleGenerateProof(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const {
        flowAccountProof,
        coaOwnershipProof,
        challenge,
        messageHash,
        erc4337Operation,
      }: ProofGenerationRequest = req.body;

      // Auto-detect proof type and route to appropriate handler
      if (coaOwnershipProof) {
        // Use official COA ownership proof
        return this.handleGenerateCOAProof(req, res);
      } else if (flowAccountProof) {
        // Use legacy Flow account proof
        // Validate input
        if (!challenge || !messageHash) {
          res.status(400).json({
            success: false,
            error: "Missing required fields: challenge, messageHash",
          });
          return;
        }

        // Generate off-chain ZK proof
        const proof = await offChainZKPGenerator.generateOwnershipProof({
          flowAccountProof,
          challenge,
          messageHash,
          erc4337Operation,
        });

        // Format for UserOperation
        const userOpSignature =
          offChainZKPGenerator.formatForUserOperation(proof);

        this.stats.totalProofsGenerated++;

        const response: ProofResponse = {
          success: true,
          proof,
          userOpSignature,
          commitment: proof.metadata.commitment,
          nullifier: proof.metadata.nullifier,
        };

        res.json(response);
      } else {
        res.status(400).json({
          success: false,
          error: "Either flowAccountProof or coaOwnershipProof is required",
        });
      }
    } catch (error) {
      console.error("Proof generation failed:", error);
      this.stats.totalProofFailures++;

      res.status(500).json({
        success: false,
        error: `Proof generation failed: ${(error as Error).message}`,
      });
    }
  }

  /**
   * Handle ZK proof verification
   */
  private async handleVerifyProof(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const { proof }: { proof: OffChainZKProof } = req.body;

      if (!proof) {
        res.status(400).json({
          success: false,
          error: "Missing proof data",
        });
        return;
      }

      const isValid = await offChainZKPGenerator.verifyProof(proof);

      res.json({
        success: true,
        valid: isValid,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Proof verification failed:", error);
      res.status(500).json({
        success: false,
        error: "Proof verification failed",
      });
    }
  }

  /**
   * Handle COA registration (official Flow EVM proof)
   */
  private async handleCOARegistration(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const {
        coaOwnershipProof,
        challenge,
        erc4337AccountAddress,
      }: COARegistrationRequest = req.body;

      // Validate input
      if (!coaOwnershipProof || !challenge || !erc4337AccountAddress) {
        res.status(400).json({
          success: false,
          error:
            "Missing required fields: coaOwnershipProof, challenge, erc4337AccountAddress",
        });
        return;
      }

      // Verify COA ownership proof
      const verificationResult =
        await flowAccountProofService.verifyCOAOwnershipProof(
          coaOwnershipProof,
          challenge
        );

      if (!verificationResult.verificationResult) {
        res.status(400).json({
          success: false,
          error: "COA ownership proof verification failed",
        });
        return;
      }

      this.stats.totalAccountsRegistered++;

      const response: AccountRegistrationResponse = {
        success: true,
        commitment: verificationResult.commitment,
        accountAddress: erc4337AccountAddress,
      };

      res.json(response);
    } catch (error) {
      console.error("COA registration failed:", error);
      res.status(500).json({
        success: false,
        error: "COA registration failed",
      });
    }
  }

  /**
   * Handle account registration (legacy method with auto-detection)
   */
  private async handleAccountRegistration(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const {
        flowAccountProof,
        coaOwnershipProof,
        challenge,
        erc4337AccountAddress,
      }: AccountRegistrationRequest = req.body;

      // Auto-detect proof type
      if (coaOwnershipProof) {
        // Use official COA ownership proof
        return this.handleCOARegistration(req, res);
      } else if (flowAccountProof) {
        // Use legacy Flow account proof
        // Validate input
        if (!challenge || !erc4337AccountAddress) {
          res.status(400).json({
            success: false,
            error: "Missing required fields: challenge, erc4337AccountAddress",
          });
          return;
        }

        // Verify Flow account proof
        const verificationResult =
          await flowAccountProofService.verifyAccountProof(
            flowAccountProof,
            challenge
          );

        if (!verificationResult.verificationResult) {
          res.status(400).json({
            success: false,
            error: "Flow account proof verification failed",
          });
          return;
        }

        this.stats.totalAccountsRegistered++;

        const response: AccountRegistrationResponse = {
          success: true,
          commitment: verificationResult.commitment,
          accountAddress: erc4337AccountAddress,
        };

        res.json(response);
      } else {
        res.status(400).json({
          success: false,
          error: "Either flowAccountProof or coaOwnershipProof is required",
        });
      }
    } catch (error) {
      console.error("Account registration failed:", error);
      res.status(500).json({
        success: false,
        error: "Account registration failed",
      });
    }
  }

  /**
   * Handle batch proof generation
   */
  private async handleBatchGenerateProofs(
    req: express.Request,
    res: express.Response
  ): Promise<void> {
    try {
      const { requests }: { requests: ProofGenerationRequest[] } = req.body;

      if (!Array.isArray(requests) || requests.length === 0) {
        res.status(400).json({
          success: false,
          error: "Invalid requests array",
        });
        return;
      }

      // Limit batch size
      if (requests.length > 10) {
        res.status(400).json({
          success: false,
          error: "Batch size limited to 10 requests",
        });
        return;
      }

      const proofs = await offChainZKPGenerator.batchGenerateProofs(requests);
      this.stats.totalProofsGenerated += proofs.length;

      res.json({
        success: true,
        proofs,
        count: proofs.length,
      });
    } catch (error) {
      console.error("Batch proof generation failed:", error);
      res.status(500).json({
        success: false,
        error: "Batch proof generation failed",
      });
    }
  }

  /**
   * Start the service
   */
  public async start(): Promise<void> {
    if (this.isRunning) {
      console.log("Service is already running");
      return;
    }

    return new Promise((resolve) => {
      const server = this.app.listen(this.config.port, () => {
        console.log(
          `🚀 Off-Chain Proof Service running on port ${this.config.port}`
        );
        console.log(
          `📊 Health check: http://localhost:${this.config.port}/health`
        );
        console.log(
          `📚 API docs: http://localhost:${this.config.port}/api/docs`
        );
        console.log(`🔒 Privacy-preserving Flow account proofs enabled!`);
        this.isRunning = true;
        resolve();
      });

      // Graceful shutdown
      process.on("SIGTERM", () => {
        console.log("SIGTERM received, shutting down gracefully");
        server.close(() => {
          console.log("Process terminated");
          process.exit(0);
        });
      });
    });
  }

  /**
   * Get service statistics
   */
  public getStats() {
    return { ...this.stats };
  }

  /**
   * Create proof service client
   */
  public static createClient(baseUrl: string) {
    return new OffChainProofServiceClient(baseUrl);
  }
}

/**
 * Client for the off-chain proof service
 */
export class OffChainProofServiceClient {
  constructor(private baseUrl: string) {}

  async generateChallenge(): Promise<ChallengeResponse> {
    const response = await fetch(`${this.baseUrl}/api/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    return response.json() as Promise<ChallengeResponse>;
  }

  async generateProof(request: ProofGenerationRequest): Promise<ProofResponse> {
    const response = await fetch(`${this.baseUrl}/api/proof/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    return response.json() as Promise<ProofResponse>;
  }

  async verifyProof(
    proof: OffChainZKProof
  ): Promise<{ success: boolean; valid: boolean }> {
    const response = await fetch(`${this.baseUrl}/api/proof/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof }),
    });
    return response.json() as Promise<{ success: boolean; valid: boolean }>;
  }

  async registerAccount(
    request: AccountRegistrationRequest
  ): Promise<AccountRegistrationResponse> {
    const response = await fetch(`${this.baseUrl}/api/account/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    return response.json() as Promise<AccountRegistrationResponse>;
  }

  async getStats(): Promise<any> {
    const response = await fetch(`${this.baseUrl}/api/stats`);
    return response.json();
  }
}

// Export default instance
export const proofService = new OffChainProofService();
