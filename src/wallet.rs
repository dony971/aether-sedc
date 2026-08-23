//! # Wallet Module
//!
//! Provides cryptographic key generation, signing, and verification for transactions.
//! Uses Ed25519 for digital signatures with BIP39 mnemonic support.
//!
//! Wallet files are ALWAYS encrypted at rest with Argon2id (password-based KDF)
//! and a single AES-256-GCM payload (secret key + mnemonic share one fresh
//! 96-bit nonce). Plaintext wallet files are never written.

use crate::transaction::{Address, Transaction};
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Signer, Verifier};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;

/// Convert public key to human-readable address with checksum
/// Format: AETH<hex_encoded_public_key_20_bytes><checksum_4_bytes>
pub fn public_key_to_address(public_key: &[u8]) -> String {
    // Use first 20 bytes of public key for shorter address
    let key_bytes = &public_key[..20.min(public_key.len())];

    // Double SHA256 for checksum
    let hash1 = sha2::Sha256::digest(key_bytes);
    let hash2 = sha2::Sha256::digest(&hash1);
    let checksum = &hash2[..4]; // First 4 bytes as checksum

    // Combine key + checksum
    let mut combined = Vec::with_capacity(key_bytes.len() + checksum.len());
    combined.extend_from_slice(key_bytes);
    combined.extend_from_slice(checksum);

    // Encode to hex and prefix
    format!("AETH{}", hex::encode(combined))
}

/// Verify address checksum
pub fn verify_address_checksum(address: &str) -> bool {
    if !address.starts_with("AETH") {
        return false;
    }

    let hex_part = &address[4..]; // Remove "AETH" prefix

    // Decode hex
    let decoded = match hex::decode(hex_part) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    if decoded.len() < 24 {
        return false; // 20 bytes key + 4 bytes checksum
    }

    let key_bytes = &decoded[..20];
    let checksum = &decoded[20..24];

    // Recompute checksum
    let hash1 = sha2::Sha256::digest(key_bytes);
    let hash2 = sha2::Sha256::digest(&hash1);
    let expected_checksum = &hash2[..4];

    checksum == expected_checksum
}

/// Wallet payload that is encrypted (secret key + mnemonic in ONE payload so
/// the AES-GCM nonce is never reused across ciphertexts).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletPayload {
    secret_key_hex: String,
    mnemonic: Option<String>,
}

/// Encrypted wallet structure for secure storage (v2: Argon2id + single payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Format version (2 = Argon2id, single payload)
    pub version: u32,
    /// KDF name ("argon2id")
    pub kdf: String,
    /// Salt for key derivation (hex)
    pub salt: String,
    /// Fresh nonce for AES-GCM (hex, 12 bytes)
    pub nonce: String,
    /// Public key (not encrypted, for address derivation)
    pub public_key_hex: String,
    /// Single encrypted payload: WalletPayload JSON (hex)
    pub payload: String,
}

/// Legacy v1 wallet format (PBKDF2, dual payload). Read-only, for migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyEncryptedWallet {
    encrypted_secret: String,
    salt: String,
    nonce: String,
    public_key_hex: String,
    encrypted_mnemonic: String,
}

/// Argon2id parameters (OWASP-recommended for 2023+: 64 MiB, t=3, p=1)
const ARGON2_M_COST: u32 = 65_536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const KDF_SALT_LEN: usize = 16;
const AES_NONCE_LEN: usize = 12;

/// Derive a 256-bit encryption key from a password using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2id key derivation failed: {}", e))?;
    Ok(key)
}

/// Reconstruct a wallet only after checking that all persisted material belongs
/// to the same keypair. `public_key_hex` is deliberately stored outside the
/// encrypted payload so clients can display an address while locked; it must
/// therefore be authenticated by this verification after decryption.
fn wallet_from_material(
    public_key_hex: String,
    secret_key_hex: String,
    mnemonic: Option<String>,
) -> Result<Wallet, Box<dyn std::error::Error>> {
    let secret_bytes = hex::decode(&secret_key_hex)?;
    if secret_bytes.len() != 32 {
        return Err("Invalid decrypted secret key length".into());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let expected_public_key =
        hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes());

    if public_key_hex != expected_public_key {
        return Err("Wallet public key does not match decrypted secret key".into());
    }

    if let Some(phrase) = &mnemonic {
        let parsed = Mnemonic::parse_in(Language::English, phrase)?;
        let seed = parsed.to_seed("");
        if seed[..32] != secret {
            return Err("Wallet mnemonic does not match decrypted secret key".into());
        }
    }

    Ok(Wallet {
        public_key_hex,
        secret_key_hex,
        mnemonic,
    })
}

/// Wallet structure holding the keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Public key (hex string)
    pub public_key_hex: String,
    /// Secret key (hex string)
    pub secret_key_hex: String,
    /// BIP39 mnemonic phrase
    pub mnemonic: Option<String>,
}

impl Wallet {
    /// Generate a new wallet with a random keypair
    pub fn new() -> Self {
        let mut secret_key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_key_bytes);
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();
        Wallet {
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            secret_key_hex: hex::encode(signing_key.to_bytes()),
            mnemonic: None,
        }
    }

    /// Generate a new wallet with BIP39 mnemonic
    pub fn new_with_mnemonic() -> Self {
        // Generate random entropy
        let mut entropy = [0u8; 16]; // 128 bits for 12 words
        rand::rngs::OsRng.fill_bytes(&mut entropy);

        // Generate mnemonic from entropy. H8: 128 bits is always a valid BIP39
        // length — a failure here is a library bug, never a reason to fall
        // back to zero entropy (which would mint a PREDICTABLE keypair).
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .expect("128-bit entropy is always a valid BIP39 mnemonic");
        let mnemonic_phrase = mnemonic.to_string();

        // Derive seed from mnemonic using BIP39
        let seed = mnemonic.to_seed("");

        // Use first 32 bytes of seed as private key
        let mut secret_key_bytes = [0u8; 32];
        secret_key_bytes.copy_from_slice(&seed[..32]);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        Wallet {
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            secret_key_hex: hex::encode(signing_key.to_bytes()),
            mnemonic: Some(mnemonic_phrase),
        }
    }

    /// Restore wallet from a secret key hex string
    pub fn from_secret_key(secret_key_hex: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let secret_bytes = hex::decode(secret_key_hex)?;
        if secret_bytes.len() != 32 {
            return Err("Invalid secret key length (expected 64 hex chars)".into());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&secret_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Wallet {
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            secret_key_hex: hex::encode(signing_key.to_bytes()),
            mnemonic: None,
        })
    }

    /// Restore wallet from BIP39 mnemonic
    pub fn from_mnemonic(mnemonic_phrase: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
        let seed = mnemonic.to_seed("");

        let mut secret_key_bytes = [0u8; 32];
        secret_key_bytes.copy_from_slice(&seed[..32]);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Wallet {
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            secret_key_hex: hex::encode(signing_key.to_bytes()),
            mnemonic: Some(mnemonic_phrase.to_string()),
        })
    }

    /// Encrypt wallet with password (Argon2id + AES-256-GCM, single payload)
    pub fn encrypt(&self, password: &str) -> Result<EncryptedWallet, Box<dyn std::error::Error>> {
        if password.is_empty() {
            return Err("Password must not be empty".into());
        }

        // Never persist internally inconsistent key material.
        wallet_from_material(
            self.public_key_hex.clone(),
            self.secret_key_hex.clone(),
            self.mnemonic.clone(),
        )?;

        // Generate fresh salt and derive the encryption key
        let mut salt = [0u8; KDF_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key_bytes = derive_key(password, &salt)?;

        // Generate a FRESH nonce for this encryption (never reused)
        let mut nonce_bytes = [0u8; AES_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Single payload: secret key + mnemonic encrypted together
        let payload = WalletPayload {
            secret_key_hex: self.secret_key_hex.clone(),
            mnemonic: self.mnemonic.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload)?;

        let cipher = Aes256Gcm::new(Key::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, payload_bytes.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(EncryptedWallet {
            version: 2,
            kdf: "argon2id".to_string(),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce_bytes),
            public_key_hex: self.public_key_hex.clone(),
            payload: hex::encode(encrypted),
        })
    }

    /// Decrypt wallet with password (Argon2id + AES-256-GCM, single payload)
    pub fn decrypt(
        encrypted: &EncryptedWallet,
        password: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if encrypted.version != 2 || encrypted.kdf != "argon2id" {
            return Err(format!(
                "Unsupported wallet format (version={}, kdf={})",
                encrypted.version, encrypted.kdf
            )
            .into());
        }

        let salt = hex::decode(&encrypted.salt)?;
        if salt.len() != KDF_SALT_LEN {
            return Err("Invalid wallet salt length".into());
        }
        let key_bytes = derive_key(password, &salt)?;

        let nonce_bytes = hex::decode(&encrypted.nonce)?;
        if nonce_bytes.len() != AES_NONCE_LEN {
            return Err("Invalid wallet nonce length".into());
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_payload = hex::decode(&encrypted.payload)?;
        let cipher = Aes256Gcm::new(Key::from_slice(&key_bytes));
        let payload_bytes = cipher
            .decrypt(nonce, encrypted_payload.as_ref())
            .map_err(|_| "Decryption failed: wrong password or corrupted file")?;

        let payload: WalletPayload = serde_json::from_slice(&payload_bytes)?;

        wallet_from_material(
            encrypted.public_key_hex.clone(),
            payload.secret_key_hex,
            payload.mnemonic,
        )
    }

    /// Decrypt a legacy v1 wallet (PBKDF2, dual payload) — migration support.
    /// Nonce reuse existed in v1 (same nonce for both payloads); v1 files are
    /// only accepted for reading so they can be re-encrypted as v2.
    fn decrypt_legacy(
        encrypted: &LegacyEncryptedWallet,
        password: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let salt = hex::decode(&encrypted.salt)?;
        if salt.len() != KDF_SALT_LEN {
            return Err("Invalid legacy wallet salt length".into());
        }
        let mut key_bytes = [0u8; 32];
        let iterations: u32 = 100_000;
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut key_bytes);

        let nonce_bytes = hex::decode(&encrypted.nonce)?;
        if nonce_bytes.len() != AES_NONCE_LEN {
            return Err("Invalid legacy wallet nonce length".into());
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(Key::from_slice(&key_bytes));

        let encrypted_secret = hex::decode(&encrypted.encrypted_secret)?;
        let secret_bytes = cipher
            .decrypt(nonce, encrypted_secret.as_ref())
            .map_err(|_| "Decryption failed: wrong password or corrupted file")?;

        let mnemonic = if !encrypted.encrypted_mnemonic.is_empty() {
            let encrypted_mnemonic = hex::decode(&encrypted.encrypted_mnemonic)?;
            let mnemonic_bytes = cipher
                .decrypt(nonce, encrypted_mnemonic.as_ref())
                .map_err(|_| "Decryption failed: wrong password or corrupted file")?;
            Some(String::from_utf8(mnemonic_bytes)?)
        } else {
            None
        };

        wallet_from_material(
            encrypted.public_key_hex.clone(),
            hex::encode(secret_bytes),
            mnemonic,
        )
    }

    /// Load wallet from a file (encrypted, v2 or legacy v1)
    pub async fn from_file<P: AsRef<Path>>(
        path: P,
        password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path).await?;

        if let Ok(encrypted) = serde_json::from_str::<EncryptedWallet>(&content) {
            let pwd = password.ok_or("Password required for encrypted wallet")?;
            return Self::decrypt(&encrypted, pwd);
        }

        // Legacy v1 wallet (PBKDF2) — accept for migration, never written.
        if let Ok(legacy) = serde_json::from_str::<LegacyEncryptedWallet>(&content) {
            let pwd = password.ok_or("Password required for encrypted wallet")?;
            return Self::decrypt_legacy(&legacy, pwd);
        }

        Err("Unsupported or corrupted wallet file".into())
    }

    /// Save wallet to a file. A password is REQUIRED: wallets are never
    /// persisted in plaintext (secret keys stay encrypted at rest).
    pub async fn to_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pwd = password
            .ok_or("A password is required to save a wallet (plaintext storage is disabled)")?;
        let encrypted = self.encrypt(pwd)?;
        let content = serde_json::to_string_pretty(&encrypted)?;
        fs::write(path, content).await?;
        Ok(())
    }

    /// Get the address derived from the public key (human-readable format)
    pub fn address(&self) -> Address {
        let public_key_bytes = hex::decode(&self.public_key_hex).unwrap_or_else(|_| {
            tracing::warn!("Failed to decode public key hex in wallet.address()");
            vec![0u8; 32]
        });
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&public_key_bytes[..32.min(public_key_bytes.len())]);
        addr
    }

    /// Get human-readable address string
    pub fn address_string(&self) -> String {
        let public_key_bytes = hex::decode(&self.public_key_hex).unwrap_or_else(|_| {
            tracing::warn!("Failed to decode public key hex in wallet.address_string()");
            vec![0u8; 32]
        });
        public_key_to_address(&public_key_bytes)
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        hex::decode(&self.public_key_hex).unwrap_or_else(|_| {
            tracing::warn!("Failed to decode public key hex in wallet.public_key_bytes()");
            vec![0u8; 32]
        })
    }

    /// Get public key as hex string
    pub fn get_public_key(&self) -> String {
        self.public_key_hex.clone()
    }

    /// Get public key as base58 encoded string
    pub fn get_public_key_base58(&self) -> String {
        bs58::encode(&self.public_key_bytes()).into_string()
    }

    /// Sign a transaction hash directly
    pub fn sign_transaction_hash(
        &self,
        tx_hash: &[u8],
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        let secret_key_bytes = self.secret_key_bytes();
        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice())?;

        // Sign the transaction hash
        let signature = signing_key.sign(tx_hash);
        Ok(signature)
    }

    /// Get secret key as bytes
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        hex::decode(&self.secret_key_hex).unwrap_or_else(|_| {
            tracing::warn!("Failed to decode secret key hex in wallet.secret_key_bytes()");
            vec![0u8; 64]
        })
    }

    /// Sign a transaction
    pub fn sign_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let secret_key_bytes = self.secret_key_bytes();
        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice())?;

        // Sign the transaction signing hash (excludes signature and public_key)
        let tx_hash = tx.compute_signing_hash();

        let signature = signing_key.sign(&tx_hash);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a transaction signature
    pub fn verify_transaction(tx: &Transaction) -> bool {
        let verifying_key: VerifyingKey = match VerifyingKey::try_from(tx.public_key.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                tracing::warn!("❌ Invalid public key format");
                return false;
            }
        };

        let signature = match Signature::try_from(tx.signature.as_slice()) {
            Ok(sig) => sig,
            Err(_) => {
                tracing::warn!("❌ Invalid signature format");
                return false;
            }
        };

        // Compute the signing hash (excludes signature and public_key)
        let tx_hash = tx.compute_signing_hash();

        // Verify the signature against the signing hash
        match verifying_key.verify(&tx_hash, &signature) {
            Ok(_) => {
                tracing::info!("✅ Signature verified successfully");
                true
            }
            Err(e) => {
                tracing::warn!("❌ Signature verification failed: {}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::new();
        assert_ne!(wallet.public_key_hex, hex::encode([0u8; 32]));
        assert_ne!(wallet.secret_key_hex, hex::encode([0u8; 32]));
    }

    #[tokio::test]
    async fn test_wallet_persistence() {
        let wallet = Wallet::new();
        let path = "test_wallet.json";

        wallet
            .to_file(path, Some("correct horse battery staple"))
            .await
            .expect("Failed to save wallet");
        let loaded = Wallet::from_file(path, Some("correct horse battery staple"))
            .await
            .expect("Failed to load wallet");

        assert_eq!(wallet.public_key_hex, loaded.public_key_hex);
        assert_eq!(wallet.secret_key_hex, loaded.secret_key_hex);

        // Cleanup
        tokio::fs::remove_file(path).await.ok();
    }

    #[tokio::test]
    async fn test_plaintext_save_rejected() {
        let wallet = Wallet::new();
        let path = "test_wallet_plaintext_rejected.json";

        // Saving WITHOUT a password must fail: no plaintext storage allowed.
        let result = wallet.to_file(path, None).await;
        assert!(result.is_err());
        assert!(!tokio::fs::try_exists(path).await.unwrap_or(false));

        tokio::fs::remove_file(path).await.ok();
    }

    #[tokio::test]
    async fn test_wrong_password_rejected() {
        let wallet = Wallet::new();
        let path = "test_wallet_wrong_pwd.json";

        wallet
            .to_file(path, Some("good-password-123"))
            .await
            .expect("Failed to save wallet");

        let result = Wallet::from_file(path, Some("wrong-password")).await;
        assert!(result.is_err());

        tokio::fs::remove_file(path).await.ok();
    }

    #[tokio::test]
    async fn test_encrypt_single_payload_and_fresh_nonce() {
        let wallet = Wallet::new_with_mnemonic();

        // Nonce must be fresh on every encryption (no reuse across saves).
        let e1 = wallet.encrypt("pwd-1").unwrap();
        let e2 = wallet.encrypt("pwd-1").unwrap();
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.salt, e2.salt);
        assert_ne!(e1.payload, e2.payload);

        // Secret + mnemonic live in ONE payload.
        let d = Wallet::decrypt(&e1, "pwd-1").unwrap();
        assert_eq!(d.secret_key_hex, wallet.secret_key_hex);
        assert_eq!(d.mnemonic, wallet.mnemonic);
    }

    #[test]
    fn test_decrypt_rejects_tampered_public_key_metadata() {
        let wallet = Wallet::new_with_mnemonic();
        let mut encrypted = wallet.encrypt("wallet-test-password").unwrap();

        // The public key is visible while a wallet is locked, but it must not
        // be accepted if an attacker swaps it in the serialized metadata.
        encrypted.public_key_hex = Wallet::new().public_key_hex;
        assert!(Wallet::decrypt(&encrypted, "wallet-test-password").is_err());
    }

    #[test]
    fn test_decrypt_rejects_invalid_kdf_lengths_without_panicking() {
        let wallet = Wallet::new();
        let mut encrypted = wallet.encrypt("wallet-test-password").unwrap();
        encrypted.nonce = hex::encode([0u8; AES_NONCE_LEN - 1]);
        assert!(Wallet::decrypt(&encrypted, "wallet-test-password").is_err());

        let mut encrypted = wallet.encrypt("wallet-test-password").unwrap();
        encrypted.salt = hex::encode([0u8; KDF_SALT_LEN - 1]);
        assert!(Wallet::decrypt(&encrypted, "wallet-test-password").is_err());
    }

    #[test]
    fn test_sign_verify() {
        let wallet = Wallet::new();
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            wallet.address(),
            [1u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            wallet.public_key_bytes(),
        );

        let signature = wallet.sign_transaction(&tx).unwrap();
        let mut signed_tx = tx.clone();
        signed_tx.signature = signature;

        assert!(Wallet::verify_transaction(&signed_tx));
    }

    #[test]
    fn test_invalid_signature() {
        let wallet = Wallet::new();
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            wallet.address(),
            [1u8; 32],
            100,
            10,
            1234567890,
            0,
            1,              // account_nonce
            vec![99u8; 64], // Invalid signature
            wallet.public_key_bytes(),
        );

        assert!(!Wallet::verify_transaction(&tx));
    }

    #[tokio::test]
    async fn test_sign_verify_with_persistence() {
        let wallet = Wallet::new();
        let path = "test_wallet_persistence.json";

        // Save wallet
        wallet
            .to_file(path, Some("pwd-with-persistence"))
            .await
            .expect("Failed to save wallet");

        // Load wallet
        let loaded_wallet = Wallet::from_file(path, Some("pwd-with-persistence"))
            .await
            .expect("Failed to load wallet");

        // Create test transaction
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            loaded_wallet.address(),
            [1u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            loaded_wallet.public_key_bytes(),
        );

        // Sign with loaded wallet
        let signature = loaded_wallet
            .sign_transaction(&tx)
            .expect("Failed to sign transaction");
        let mut signed_tx = tx.clone();
        signed_tx.signature = signature;

        // Verify signature
        assert!(Wallet::verify_transaction(&signed_tx));

        // Cleanup
        tokio::fs::remove_file(path).await.ok();
    }

    #[tokio::test]
    async fn test_generate_save_load_sign_loop() {
        // Generate wallet
        let wallet = Wallet::new();
        let path = "test_wallet_loop.json";

        // Save wallet
        wallet
            .to_file(path, Some("pwd-loop"))
            .await
            .expect("Failed to save wallet");

        // Load wallet
        let loaded_wallet = Wallet::from_file(path, Some("pwd-loop"))
            .await
            .expect("Failed to load wallet");

        // Create test transaction
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            loaded_wallet.address(),
            [1u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            loaded_wallet.public_key_bytes(),
        );

        // Sign with loaded wallet
        let signature = loaded_wallet
            .sign_transaction(&tx)
            .expect("Failed to sign transaction");
        let mut signed_tx = tx.clone();
        signed_tx.signature = signature;

        // Verify signature
        assert!(Wallet::verify_transaction(&signed_tx));

        // Cleanup
        tokio::fs::remove_file(path).await.ok();
    }
}
