// FlowKeyRegister.cdc - Global upgradable contract for managing Flow account keys
// This contract exposes active Flow public keys for cross-chain verification

import "FlowToken"

access(all) contract FlowKeyRegister {
    
    // Events
    access(all) event KeysUpdated(account: Address, keyCount: UInt32, blockHeight: UInt64)
    access(all) event ContractUpgraded(version: String)
    
    // Storage paths
    access(all) let AdminStoragePath: StoragePath
    access(all) let AdminCapabilityPath: CapabilityPath
    
    // Contract version for upgrade tracking
    access(all) var version: String
    
    // Key data structure matching Flow's internal representation
    access(all) struct FlowKey {
        access(all) let publicKey: String      // Hex-encoded, uncompressed, no 04 prefix
        access(all) let weight: UFix64         // Key weight for multi-sig
        access(all) let hashAlgorithm: UInt8   // Hash algorithm identifier
        access(all) let signatureAlgorithm: UInt8 // Signature algorithm (1=ECDSA_P256, 2=ECDSA_secp256k1)
        access(all) let isRevoked: Bool        // Key revocation status
        access(all) let keyIndex: Int          // Original key index in account
        
        init(
            publicKey: String,
            weight: UFix64,
            hashAlgorithm: UInt8,
            signatureAlgorithm: UInt8,
            isRevoked: Bool,
            keyIndex: Int
        ) {
            self.publicKey = publicKey
            self.weight = weight
            self.hashAlgorithm = hashAlgorithm
            self.signatureAlgorithm = signatureAlgorithm
            self.isRevoked = isRevoked
            self.keyIndex = keyIndex
        }
    }
    
    // Admin resource for contract upgrades and management
    access(all) resource Admin {
        access(all) fun upgradeContract(version: String) {
            FlowKeyRegister.version = version
            emit ContractUpgraded(version: version)
        }
    }
    
    // Main function to get active keys for an account
    // Returns keys in their original Flow account order (by keyIndex)
    access(all) fun getKeys(account: Address): [FlowKey] {
        let keys: [FlowKey] = []
        let accountRef = getAccount(account)
        
        // Iterate through all keys on the account
        for keyIndex in accountRef.keys.keys {
            if let key = accountRef.keys.get(keyIndex: keyIndex) {
                // Only include active (non-revoked) keys that support p256 or secp256k1
                if !key.isRevoked && (key.signatureAlgorithm == SignatureAlgorithm.ECDSA_P256 || key.signatureAlgorithm == SignatureAlgorithm.ECDSA_secp256k1) {
                    
                    // Convert public key to hex string without 04 prefix
                    let pubKeyHex = self.formatPublicKey(key.publicKey)
                    
                    let flowKey = FlowKey(
                        publicKey: pubKeyHex,
                        weight: key.weight,
                        hashAlgorithm: key.hashAlgorithm.rawValue,
                        signatureAlgorithm: key.signatureAlgorithm.rawValue,
                        isRevoked: key.isRevoked,
                        keyIndex: keyIndex
                    )
                    keys.append(flowKey)
                }
            }
        }
        
        // Sort by keyIndex to maintain Flow account order
        let sortedKeys = keys.sort { (a: FlowKey, b: FlowKey): Bool => a.keyIndex < b.keyIndex }
        
        emit KeysUpdated(account: account, keyCount: UInt32(sortedKeys.length), blockHeight: getCurrentBlock().height)
        return sortedKeys
    }
    
    // Get keys count for an account (lighter weight query)
    access(all) fun getKeyCount(account: Address): UInt32 {
        let accountRef = getAccount(account)
        var count: UInt32 = 0
        
        for keyIndex in accountRef.keys.keys {
            if let key = accountRef.keys.get(keyIndex: keyIndex) {
                if !key.isRevoked && (key.signatureAlgorithm == SignatureAlgorithm.ECDSA_P256 || key.signatureAlgorithm == SignatureAlgorithm.ECDSA_secp256k1) {
                    count = count + 1
                }
            }
        }
        
        return count
    }
    
    // Check if a specific public key is active for an account
    access(all) fun isKeyActive(account: Address, publicKey: String): Bool {
        let keys = self.getKeys(account: account)
        for key in keys {
            if key.publicKey == publicKey {
                return true
            }
        }
        return false
    }
    
    // Format public key by removing 04 prefix if present
    access(self) fun formatPublicKey(_ publicKey: PublicKey): String {
        let keyBytes = publicKey.publicKey
        let keyHex = String.encodeHex(keyBytes)
        
        // Remove 04 prefix if present (uncompressed format indicator)
        if keyHex.length > 2 && keyHex.slice(from: 0, upTo: 2) == "04" {
            return keyHex.slice(from: 2, upTo: keyHex.length)
        }
        
        return keyHex
    }
    
    // Get contract version
    access(all) fun getVersion(): String {
        return self.version
    }
    
    // Get current block height for external services
    access(all) fun getCurrentBlockHeight(): UInt64 {
        return getCurrentBlock().height
    }
    
    init() {
        self.version = "1.0.0"
        self.AdminStoragePath = /storage/FlowKeyRegisterAdmin
        self.AdminCapabilityPath = /private/FlowKeyRegisterAdmin
        
        // Create admin resource
        let admin <- create Admin()
        self.account.save(<-admin, to: self.AdminStoragePath)
        
        // Create private capability for admin
        self.account.link<&Admin>(
            self.AdminCapabilityPath,
            target: self.AdminStoragePath
        )
    }
}