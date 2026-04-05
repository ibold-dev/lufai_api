//! Cryptographically random login secrets (admin shows plaintext once; DB stores Argon2 hash).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::RngCore;

/// URL-safe base64 (no padding), 32 random bytes (~43 characters).
pub fn generate_login_secret() -> String {
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}
