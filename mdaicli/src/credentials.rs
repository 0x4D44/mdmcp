use crate::errors::{AppError, ErrorKind};
use aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use directories::BaseDirs;
use rand::RngCore;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const SERVICE_NAME: &str = "mdaicli";

pub enum StorageMethod {
    Keyring,
    FallbackFile,
}

pub fn store_secret(
    provider: &str,
    account: &str,
    secret: &str,
) -> Result<StorageMethod, AppError> {
    // Try OS keyring first
    if store_keyring(provider, account, secret).is_ok() {
        return Ok(StorageMethod::Keyring);
    }
    // Fallback to encrypted file
    store_fallback(provider, account, secret)?;
    Ok(StorageMethod::FallbackFile)
}

pub fn retrieve_secret(provider: &str, account: &str) -> Result<String, AppError> {
    // Test override for integration tests
    let env_key = format!("MDAICLI_TEST_SECRET_{}", provider.to_uppercase());
    if let Ok(v) = std::env::var(env_key) { return Ok(v); }
    if let Ok(v) = std::env::var("MDAICLI_TEST_SECRET") { return Ok(v); }
    if let Ok(s) = get_keyring(provider, account) {
        return Ok(s);
    }
    get_fallback(provider, account)
}

pub fn remove_secret(provider: &str, account: &str) -> Result<(), AppError> {
    let _ = remove_keyring(provider, account);
    let _ = remove_fallback(provider, account);
    Ok(())
}

fn store_keyring(provider: &str, account: &str, secret: &str) -> Result<(), AppError> {
    let entry =
        keyring::Entry::new(SERVICE_NAME, &format!("{}:{}", provider, account)).map_err(|e| {
            AppError {
                kind: ErrorKind::Credential,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            }
        })?;
    entry.set_password(secret).map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })
}

fn get_keyring(provider: &str, account: &str) -> Result<String, AppError> {
    let entry =
        keyring::Entry::new(SERVICE_NAME, &format!("{}:{}", provider, account)).map_err(|e| {
            AppError {
                kind: ErrorKind::Credential,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            }
        })?;
    entry.get_password().map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })
}

fn remove_keyring(provider: &str, account: &str) -> Result<(), AppError> {
    let entry =
        keyring::Entry::new(SERVICE_NAME, &format!("{}:{}", provider, account)).map_err(|e| {
            AppError {
                kind: ErrorKind::Credential,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            }
        })?;
    entry.delete_password().map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })
}

// --------- Fallback encrypted file storage ----------

#[derive(Serialize, Deserialize)]
struct CredFile {
    version: u32,
    kdf: KdfParams,
    entries: HashMap<String, EncEntry>,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    alg: String,
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_b64: String,
}

#[derive(Serialize, Deserialize)]
struct EncEntry {
    nonce_b64: String,
    ct_b64: String,
}

fn cred_file_path() -> PathBuf {
    if let Some(b) = BaseDirs::new() {
        b.config_dir().join("mdaicli").join("credentials.enc")
    } else {
        PathBuf::from("~/.config/mdaicli/credentials.enc")
    }
}

fn load_or_init_file() -> Result<CredFile, AppError> {
    let p = cred_file_path();
    if p.exists() {
        let s = fs::read_to_string(p)?;
        let cf: CredFile = serde_json::from_str(&s).map_err(|e| AppError {
            kind: ErrorKind::Credential,
            message: format!("Corrupt credential file: {}", e),
            source: Some(anyhow::Error::from(e)),
        })?;
        Ok(cf)
    } else {
        // New file with random salt
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let cf = CredFile {
            version: 1,
            kdf: KdfParams {
                alg: "argon2id".into(),
                mem_kib: 65536,
                iterations: 3,
                parallelism: 4,
                salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
            },
            entries: HashMap::new(),
        };
        Ok(cf)
    }
}

fn save_file(cf: &CredFile) -> Result<(), AppError> {
    let p = cred_file_path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(cf).map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    fs::write(p, s)?;
    Ok(())
}

fn prompt_passphrase(confirm_if_new: bool) -> Result<String, AppError> {
    eprint!("Enter credentials store passphrase: ");
    let pass = read_password().map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if pass.is_empty() {
        return Err(AppError::with_kind(
            ErrorKind::Credential,
            "Empty passphrase",
        ));
    }
    if confirm_if_new {
        eprint!("Confirm passphrase: ");
        let confirm = read_password().map_err(|e| AppError {
            kind: ErrorKind::Credential,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        if pass != confirm {
            return Err(AppError::with_kind(
                ErrorKind::Credential,
                "Passphrases do not match",
            ));
        }
    }
    Ok(pass)
}

fn derive_key(kdf: &KdfParams, pass: &str) -> Result<[u8; 32], AppError> {
    let params = Params::new(kdf.mem_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|e| AppError::with_kind(ErrorKind::Credential, e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&kdf.salt_b64)
        .map_err(|e| AppError::with_kind(ErrorKind::Credential, e.to_string()))?;
    let mut out = [0u8; 32];
    argon
        .hash_password_into(pass.as_bytes(), &salt_bytes, &mut out)
        .map_err(|e| AppError::with_kind(ErrorKind::Credential, e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_derivation_is_deterministic() {
        let kdf = KdfParams {
            alg: "argon2id".into(),
            mem_kib: 65536,
            iterations: 3,
            parallelism: 4,
            salt_b64: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        };
        let k1 = derive_key(&kdf, "passphrase").unwrap();
        let k2 = derive_key(&kdf, "passphrase").unwrap();
        assert_eq!(k1, k2);
        let k3 = derive_key(&kdf, "other").unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn aes_gcm_roundtrip_and_tamper_detect() {
        let key = [9u8; 32];
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        let nonce = [1u8; 12];
        let nonce_ga = GenericArray::from_slice(&nonce);
        let ct = cipher.encrypt(nonce_ga, b"secret".as_ref()).unwrap();
        let pt = cipher.decrypt(nonce_ga, ct.as_ref()).unwrap();
        assert_eq!(pt, b"secret");
        // Tamper
        let mut bad = ct.clone();
        bad[0] ^= 0xFF;
        assert!(cipher.decrypt(nonce_ga, bad.as_ref()).is_err());
    }
}

fn store_fallback(provider: &str, account: &str, secret: &str) -> Result<(), AppError> {
    let mut cf = load_or_init_file()?;
    let is_new = cf.entries.is_empty();
    let pass = prompt_passphrase(is_new)?;
    let key = derive_key(&cf.kdf, &pass)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);
    let ct = cipher
        .encrypt(nonce_ga, secret.as_bytes())
        .map_err(|_| AppError::with_kind(ErrorKind::Credential, "Encryption failed"))?;
    let entry_key = format!("{}:{}", provider, account);
    cf.entries.insert(
        entry_key,
        EncEntry {
            nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce),
            ct_b64: base64::engine::general_purpose::STANDARD.encode(ct),
        },
    );
    save_file(&cf)
}

fn get_fallback(provider: &str, account: &str) -> Result<String, AppError> {
    let cf = load_or_init_file()?;
    let entry_key = format!("{}:{}", provider, account);
    let enc = cf.entries.get(&entry_key).ok_or_else(|| {
        AppError::with_kind(ErrorKind::Credential, "No credentials found for account")
    })?;
    let pass = prompt_passphrase(false)?;
    let key = derive_key(&cf.kdf, &pass)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(&enc.nonce_b64)
        .map_err(|e| AppError {
            kind: ErrorKind::Credential,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let nonce_ga = GenericArray::from_slice(&nonce);
    let ct = base64::engine::general_purpose::STANDARD
        .decode(&enc.ct_b64)
        .map_err(|e| AppError {
            kind: ErrorKind::Credential,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let pt = cipher.decrypt(nonce_ga, ct.as_ref()).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Invalid passphrase or corrupted data",
        )
    })?;
    let s = String::from_utf8(pt).map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    Ok(s)
}

fn remove_fallback(provider: &str, account: &str) -> Result<(), AppError> {
    let mut cf = load_or_init_file()?;
    let entry_key = format!("{}:{}", provider, account);
    cf.entries.remove(&entry_key);
    save_file(&cf)
}
