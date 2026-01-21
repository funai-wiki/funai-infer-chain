// Copyright (C) 2020-2024 Funai Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Encryption module for inference request input data.
//! 
//! This module provides ECIES (Elliptic Curve Integrated Encryption Scheme) based
//! encryption/decryption for protecting user inference inputs.
//!
//! ## Why ECIES (Hybrid Encryption)?
//! 
//! ECIES combines asymmetric (ECC) and symmetric (AES) encryption:
//! 1. **Asymmetric part**: ECDH key agreement to derive a shared secret
//! 2. **Symmetric part**: AES-GCM for actual data encryption
//!
//! This hybrid approach is necessary because:
//! - Pure asymmetric encryption (RSA/ECC) can only encrypt very small data
//! - Symmetric encryption (AES) is fast and can encrypt any size data
//! - ECIES combines the security of asymmetric key exchange with the efficiency of symmetric encryption
//!
//! ## Flow:
//! 1. User submits plaintext input to Signer
//! 2. Signer encrypts input using ECIES (ECDH + AES-GCM)
//! 3. Infer Node requests decryption from Signer to execute inference
//! 4. Transaction contains encrypted input
//! 5. Other Signers verify by requesting decryption from original Signer

use funai_common::types::chainstate::FunaiPrivateKey;
use funai_common::util::secp256k1::Secp256k1PublicKey;
use funai_common::util::hash::{Sha256Sum, hex_bytes, to_hex};
use funailib::burnchains::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use secp256k1::{SecretKey, PublicKey as Secp256k1PubKey, Secp256k1};

/// Encryption error types
#[derive(Debug, Clone)]
pub enum EncryptionError {
    /// Key generation error
    KeyGenerationError(String),
    /// Encryption error
    EncryptionFailed(String),
    /// Decryption error
    DecryptionFailed(String),
    /// Invalid data format
    InvalidFormat(String),
    /// Signature verification failed
    SignatureVerificationFailed(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::KeyGenerationError(s) => write!(f, "Key generation error: {}", s),
            EncryptionError::EncryptionFailed(s) => write!(f, "Encryption failed: {}", s),
            EncryptionError::DecryptionFailed(s) => write!(f, "Decryption failed: {}", s),
            EncryptionError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            EncryptionError::SignatureVerificationFailed(s) => write!(f, "Signature verification failed: {}", s),
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Encrypted data structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The signer's public key (hex encoded) that was used for encryption
    pub signer_public_key: String,
    /// Ephemeral public key (hex encoded) for ECDH
    pub ephemeral_public_key: String,
    /// Encrypted ciphertext (hex encoded)
    pub ciphertext: String,
    /// Nonce used for AES-GCM (hex encoded)
    pub nonce: String,
    /// Optional signature from the signer to prove authenticity
    pub signature: Option<String>,
}

impl EncryptedData {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, EncryptionError> {
        serde_json::to_string(self)
            .map_err(|e| EncryptionError::InvalidFormat(e.to_string()))
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, EncryptionError> {
        serde_json::from_str(json)
            .map_err(|e| EncryptionError::InvalidFormat(e.to_string()))
    }

    /// Serialize to hex-encoded bytes
    pub fn to_hex(&self) -> Result<String, EncryptionError> {
        let json = self.to_json()?;
        Ok(to_hex(json.as_bytes()))
    }

    /// Deserialize from hex-encoded bytes
    pub fn from_hex(hex_str: &str) -> Result<Self, EncryptionError> {
        let bytes = hex_bytes(hex_str)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid hex: {}", e)))?;
        let json = String::from_utf8(bytes)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;
        Self::from_json(&json)
    }

    /// Extract signer's public key from encrypted input without full decryption
    /// This is useful for other Signers to know which Signer to contact for decryption
    pub fn extract_signer_public_key(encrypted_input: &str) -> Result<String, EncryptionError> {
        // Try parsing as JSON first
        if let Ok(data) = Self::from_json(encrypted_input) {
            return Ok(data.signer_public_key);
        }
        
        // Try parsing as hex-encoded JSON
        if let Ok(data) = Self::from_hex(encrypted_input) {
            return Ok(data.signer_public_key);
        }
        
        Err(EncryptionError::InvalidFormat("Cannot extract signer public key from input".to_string()))
    }
}

/// Signer registry for looking up Signer endpoints by public key
/// This allows other Signers to find the encrypting Signer for decryption requests
#[derive(Clone, Debug, Default)]
pub struct SignerRegistry {
    /// Map from signer public key (hex) to endpoint URL
    signers: std::collections::HashMap<String, SignerInfo>,
}

/// Information about a registered Signer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerInfo {
    /// Signer's public key (hex encoded)
    pub public_key: String,
    /// Signer's endpoint URL for API requests
    pub endpoint: String,
    /// Signer's principal address
    pub principal: String,
    /// Last seen timestamp
    pub last_seen: u64,
}

impl SignerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            signers: std::collections::HashMap::new(),
        }
    }

    /// Register or update a Signer
    pub fn register(&mut self, info: SignerInfo) {
        self.signers.insert(info.public_key.clone(), info);
    }

    /// Look up a Signer by public key
    pub fn get_by_public_key(&self, public_key: &str) -> Option<&SignerInfo> {
        self.signers.get(public_key)
    }

    /// Get endpoint URL for a Signer by public key
    pub fn get_endpoint(&self, public_key: &str) -> Option<String> {
        self.signers.get(public_key).map(|info| info.endpoint.clone())
    }

    /// Remove a Signer from the registry
    pub fn unregister(&mut self, public_key: &str) {
        self.signers.remove(public_key);
    }

    /// Get all registered Signers
    pub fn get_all(&self) -> Vec<&SignerInfo> {
        self.signers.values().collect()
    }
}

/// Inference input encryption service
pub struct InferenceEncryption;

impl InferenceEncryption {
    /// Encrypt plaintext input using the signer's public key.
    /// 
    /// This uses a simplified ECIES-like scheme:
    /// 1. Generate ephemeral keypair
    /// 2. Derive shared secret via ECDH (simplified - using hash of public keys)
    /// 3. Use shared secret as AES-256-GCM key
    /// 4. Encrypt the plaintext
    /// 
    /// # Arguments
    /// * `plaintext` - The plaintext input to encrypt
    /// * `signer_private_key` - The signer's private key (for signature)
    /// 
    /// # Returns
    /// * `EncryptedData` - The encrypted data structure
    pub fn encrypt(
        plaintext: &str,
        signer_private_key: &FunaiPrivateKey,
    ) -> Result<EncryptedData, EncryptionError> {
        // Get signer's public key
        let signer_public_key = Secp256k1PublicKey::from_private(signer_private_key);
        let signer_pub_hex = to_hex(&signer_public_key.to_bytes_compressed());

        // Generate ephemeral keypair
        let ephemeral_private_key = FunaiPrivateKey::new();
        let ephemeral_public_key = Secp256k1PublicKey::from_private(&ephemeral_private_key);
        let ephemeral_pub_hex = to_hex(&ephemeral_public_key.to_bytes_compressed());

        // Derive shared secret (simplified: hash of concatenated public keys + ephemeral private key)
        // In production, use proper ECDH
        let shared_secret = Self::derive_shared_secret(
            &ephemeral_private_key,
            &signer_public_key,
        )?;

        // Generate random nonce for AES-GCM
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create AES-256-GCM cipher with shared secret as key
        let cipher: Aes256Gcm = Aes256Gcm::new_from_slice(&shared_secret)
            .expect("Invalid key length");

        // Encrypt the plaintext
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| EncryptionError::EncryptionFailed("Encryption failed".to_string()))?;

        // Create signature of the encrypted data for authenticity
        let signature_data = format!("{}{}{}", 
            ephemeral_pub_hex, 
            to_hex(&ciphertext), 
            to_hex(&nonce_bytes)
        );
        let signature_hash = Sha256Sum::from_data(signature_data.as_bytes());
        // Use the sign method from PrivateKey trait
        let signature = PrivateKey::sign(signer_private_key, signature_hash.as_bytes())
            .map_err(|e| EncryptionError::EncryptionFailed(format!("Signing failed: {}", e)))?;

        Ok(EncryptedData {
            signer_public_key: signer_pub_hex,
            ephemeral_public_key: ephemeral_pub_hex,
            ciphertext: to_hex(&ciphertext),
            nonce: to_hex(&nonce_bytes),
            signature: Some(to_hex(signature.as_bytes())),
        })
    }

    /// Decrypt encrypted data using the signer's private key.
    /// 
    /// # Arguments
    /// * `encrypted_data` - The encrypted data to decrypt
    /// * `signer_private_key` - The signer's private key
    /// 
    /// # Returns
    /// * The decrypted plaintext
    pub fn decrypt(
        encrypted_data: &EncryptedData,
        signer_private_key: &FunaiPrivateKey,
    ) -> Result<String, EncryptionError> {
        // Verify the signer's public key matches
        let signer_public_key = Secp256k1PublicKey::from_private(signer_private_key);
        let expected_pub_hex = to_hex(&signer_public_key.to_bytes_compressed());
        
        if encrypted_data.signer_public_key != expected_pub_hex {
            return Err(EncryptionError::DecryptionFailed(
                "Signer public key mismatch".to_string()
            ));
        }

        // Parse ephemeral public key
        let ephemeral_pub_bytes = hex_bytes(&encrypted_data.ephemeral_public_key)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid ephemeral key: {}", e)))?;
        let ephemeral_public_key = Secp256k1PublicKey::from_slice(&ephemeral_pub_bytes)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid ephemeral key: {}", e)))?;

        // Derive shared secret (must match the encryption side)
        let shared_secret = Self::derive_shared_secret_for_decrypt(
            signer_private_key,
            &ephemeral_public_key,
        )?;

        // Parse nonce and ciphertext
        let nonce_bytes = hex_bytes(&encrypted_data.nonce)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid nonce: {}", e)))?;
        let ciphertext = hex_bytes(&encrypted_data.ciphertext)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid ciphertext: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create AES-256-GCM cipher with shared secret as key
        let cipher: Aes256Gcm = Aes256Gcm::new_from_slice(&shared_secret)
            .expect("Invalid key length");

        // Decrypt
        let plaintext_bytes = cipher.decrypt(nonce, ciphertext.as_slice())
            .map_err(|_| EncryptionError::DecryptionFailed("Decryption failed".to_string()))?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Invalid UTF-8: {}", e)))
    }

    /// Verify that the encrypted data was signed by the claimed signer.
    pub fn verify_signature(
        encrypted_data: &EncryptedData,
    ) -> Result<bool, EncryptionError> {
        let signature_hex = encrypted_data.signature.as_ref()
            .ok_or_else(|| EncryptionError::SignatureVerificationFailed("No signature".to_string()))?;

        let signature_data = format!("{}{}{}", 
            encrypted_data.ephemeral_public_key, 
            encrypted_data.ciphertext, 
            encrypted_data.nonce
        );
        let signature_hash = Sha256Sum::from_data(signature_data.as_bytes());

        let pub_key_bytes = hex_bytes(&encrypted_data.signer_public_key)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid public key: {}", e)))?;
        let public_key = Secp256k1PublicKey::from_slice(&pub_key_bytes)
            .map_err(|e| EncryptionError::InvalidFormat(format!("Invalid public key: {}", e)))?;

        let sig_bytes = hex_bytes(signature_hex)
            .map_err(|_e| EncryptionError::InvalidFormat("Invalid signature hex".to_string()))?;

        // Verify signature using PublicKey trait
        if sig_bytes.len() != 65 {
            return Err(EncryptionError::InvalidFormat("Invalid signature length".to_string()));
        }
        let mut sig_arr = [0u8; 65];
        sig_arr.copy_from_slice(&sig_bytes);
        let message_sig = funai_common::util::secp256k1::MessageSignature(sig_arr);
        
        let is_valid = PublicKey::verify(&public_key, signature_hash.as_bytes(), &message_sig)
            .unwrap_or(false);

        Ok(is_valid)
    }

    /// Derive shared secret using ECDH (Elliptic Curve Diffie-Hellman)
    /// 
    /// This is the core of ECIES - both parties can derive the same shared secret:
    /// - Encryptor: uses ephemeral_private_key * recipient_public_key
    /// - Decryptor: uses recipient_private_key * ephemeral_public_key
    /// 
    /// Due to the properties of elliptic curves: a*B = b*A (where A=a*G, B=b*G)
    /// 
    /// Note: Uses shared_secret_point to get raw x-coordinate, then SHA256.
    /// This matches the SDK's implementation.
    fn derive_shared_secret(
        ephemeral_private: &FunaiPrivateKey,
        signer_public: &Secp256k1PublicKey,
    ) -> Result<[u8; 32], EncryptionError> {
        // Convert ephemeral private key to secp256k1 format
        // Note: as_slice() returns the raw 32-byte secret key, not to_bytes() which may include compression flag
        let ephemeral_sk = SecretKey::from_slice(ephemeral_private.as_slice())
            .map_err(|e| EncryptionError::KeyGenerationError(format!("Invalid ephemeral key: {}", e)))?;
        
        // Convert signer's public key to secp256k1 format
        let signer_pk = Secp256k1PubKey::from_slice(&signer_public.to_bytes_compressed())
            .map_err(|e| EncryptionError::KeyGenerationError(format!("Invalid signer public key: {}", e)))?;
        
        // Perform ECDH to get the raw shared point x-coordinate
        // Use shared_secret_point to get the raw x-coordinate (32 bytes)
        // without the default SHA256 hashing that SharedSecret::new does
        let mut x_coord = [0u8; 32];
        let shared_point = secp256k1::ecdh::shared_secret_point(&signer_pk, &ephemeral_sk);
        // shared_secret_point returns 64 bytes: x (32 bytes) || y (32 bytes)
        x_coord.copy_from_slice(&shared_point[..32]);
        
        // Hash the x-coordinate with SHA256 to get the encryption key
        let mut hasher = Sha256::new();
        hasher.update(&x_coord);
        let result = hasher.finalize();
        
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&result[..32]);
        Ok(secret)
    }

    /// Derive shared secret for decryption using ECDH
    /// 
    /// This produces the same shared secret as derive_shared_secret due to ECDH properties:
    /// signer_private * ephemeral_public = ephemeral_private * signer_public
    /// 
    /// Note: We use a custom hash function to get the raw x-coordinate, then hash it with SHA256.
    /// This matches the SDK's implementation which does:
    /// 1. ECDH to get shared point (x-coordinate)
    /// 2. SHA256(x-coordinate) to get the encryption key
    fn derive_shared_secret_for_decrypt(
        signer_private: &FunaiPrivateKey,
        ephemeral_public: &Secp256k1PublicKey,
    ) -> Result<[u8; 32], EncryptionError> {
        // Convert signer's private key to secp256k1 format
        // Note: as_slice() returns the raw 32-byte secret key
        let signer_sk = SecretKey::from_slice(signer_private.as_slice())
            .map_err(|e| EncryptionError::KeyGenerationError(format!("Invalid signer key: {}", e)))?;
        
        // Convert ephemeral public key to secp256k1 format
        let ephemeral_pk = Secp256k1PubKey::from_slice(&ephemeral_public.to_bytes_compressed())
            .map_err(|e| EncryptionError::KeyGenerationError(format!("Invalid ephemeral public key: {}", e)))?;
        
        // Perform ECDH to get the raw shared point x-coordinate
        // Use shared_secret_point to get the raw x-coordinate (32 bytes)
        // without the default SHA256 hashing that SharedSecret::new does
        let mut x_coord = [0u8; 32];
        let shared_point = secp256k1::ecdh::shared_secret_point(&ephemeral_pk, &signer_sk);
        // shared_secret_point returns 64 bytes: x (32 bytes) || y (32 bytes)
        // We only need the x-coordinate (first 32 bytes)
        x_coord.copy_from_slice(&shared_point[..32]);
        
        // Hash the x-coordinate with SHA256 to get the encryption key
        // This matches the SDK's: encryptionKey = sha256(sharedSecretX)
        let mut hasher = Sha256::new();
        hasher.update(&x_coord);
        let result = hasher.finalize();
        
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&result[..32]);
        Ok(secret)
    }
}

/// Decryption request structure (sent from Infer Node to Signer)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionRequest {
    /// Task ID for which decryption is requested
    pub task_id: String,
    /// The requester's public key (for verification)
    pub requester_public_key: String,
    /// Signature of task_id by the requester (proves they control the key)
    pub signature: String,
}

/// Decryption response structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionResponse {
    /// Task ID
    pub task_id: String,
    /// Decrypted plaintext (only sent if authorized)
    pub plaintext: Option<String>,
    /// Error message if decryption failed or unauthorized
    pub error: Option<String>,
    /// Whether the request was successful
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_data_serialization() {
        let encrypted = EncryptedData {
            signer_public_key: "0123456789abcdef".to_string(),
            ephemeral_public_key: "fedcba9876543210".to_string(),
            ciphertext: "encrypted_data_here".to_string(),
            nonce: "nonce_here".to_string(),
            signature: Some("signature_here".to_string()),
        };

        let json = encrypted.to_json().unwrap();
        let parsed = EncryptedData::from_json(&json).unwrap();
        
        assert_eq!(encrypted.signer_public_key, parsed.signer_public_key);
        assert_eq!(encrypted.ciphertext, parsed.ciphertext);
    }

    #[test]
    fn test_ecies_encrypt_decrypt() {
        // Generate a signer keypair
        let signer_private_key = FunaiPrivateKey::new();
        
        // Test plaintext
        let plaintext = "Hello, this is a secret inference input that needs to be encrypted!";
        
        // Encrypt using ECIES
        let encrypted = InferenceEncryption::encrypt(plaintext, &signer_private_key)
            .expect("Encryption should succeed");
        
        // Verify the encrypted data has the expected structure
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.ephemeral_public_key.is_empty());
        assert!(!encrypted.nonce.is_empty());
        assert!(encrypted.signature.is_some());
        
        // Decrypt using the same private key
        let decrypted = InferenceEncryption::decrypt(&encrypted, &signer_private_key)
            .expect("Decryption should succeed");
        
        // Verify the decrypted text matches the original
        assert_eq!(plaintext, decrypted);
        
        println!("ECIES encrypt/decrypt test passed!");
        println!("Original: {}", plaintext);
        println!("Decrypted: {}", decrypted);
    }

    #[test]
    fn test_ecies_wrong_key_fails() {
        // Generate two different keypairs
        let signer_private_key = FunaiPrivateKey::new();
        let wrong_private_key = FunaiPrivateKey::new();
        
        // Encrypt with signer's key
        let plaintext = "Secret message";
        let encrypted = InferenceEncryption::encrypt(plaintext, &signer_private_key)
            .expect("Encryption should succeed");
        
        // Attempt to decrypt with wrong key should fail
        let result = InferenceEncryption::decrypt(&encrypted, &wrong_private_key);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_ecies_large_input() {
        let signer_private_key = FunaiPrivateKey::new();
        
        // Test with a large input (simulating a long inference prompt)
        let large_input = "This is a very long inference input. ".repeat(1000);
        
        let encrypted = InferenceEncryption::encrypt(&large_input, &signer_private_key)
            .expect("Encryption of large input should succeed");
        
        let decrypted = InferenceEncryption::decrypt(&encrypted, &signer_private_key)
            .expect("Decryption of large input should succeed");
        
        assert_eq!(large_input, decrypted);
        println!("Large input test passed! Input size: {} bytes", large_input.len());
    }
}