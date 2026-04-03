//! Verify Google Sign-In ID tokens (JWT) using Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use rsa::pkcs8::EncodePublicKey;
use rsa::BigUint;
use rsa::RsaPublicKey;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::http::error::ApiError;

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}

#[derive(Debug, Deserialize)]
struct GoogleJwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
pub struct GoogleIdTokenClaims {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    /// Display name from Google profile (optional in token).
    #[serde(default)]
    pub name: Option<String>,
}

/// Best-effort display name from Google `name` claim for `full_name`.
pub fn google_display_name(claims: &GoogleIdTokenClaims) -> String {
    claims
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("")
        .to_string()
}

struct JwksCache {
    pem_by_kid: HashMap<String, Vec<u8>>,
    fetched_at: Instant,
}

static JWKS_CACHE: OnceLock<Mutex<Option<JwksCache>>> = OnceLock::new();

fn jwks_mutex() -> &'static Mutex<Option<JwksCache>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(None))
}

fn jwk_to_pem(jwk: &GoogleJwk) -> Result<Vec<u8>, ApiError> {
    if jwk.kty != "RSA" {
        return Err(ApiError::internal("unsupported JWK type"));
    }
    let n_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.n)
        .map_err(|_| ApiError::internal("invalid JWK n"))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.e)
        .map_err(|_| ApiError::internal("invalid JWK e"))?;
    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);
    let public_key =
        RsaPublicKey::new(n, e).map_err(|e| ApiError::internal(format!("RSA key: {e}")))?;
    public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| ApiError::internal(format!("PEM encode: {e}")))
        .map(|s| s.into_bytes())
}

async fn load_jwks(client: &Client) -> Result<HashMap<String, Vec<u8>>, ApiError> {
    let res = client
        .get(GOOGLE_JWKS_URL)
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("JWKS fetch failed: {e}")))?;
    if !res.status().is_success() {
        return Err(ApiError::internal("JWKS fetch failed"));
    }
    let jwks: GoogleJwks = res
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("JWKS parse: {e}")))?;
    let mut pem_by_kid = HashMap::new();
    for key in jwks.keys {
        if key.kty != "RSA" {
            continue;
        }
        let pem = jwk_to_pem(&key)?;
        pem_by_kid.insert(key.kid, pem);
    }
    if pem_by_kid.is_empty() {
        return Err(ApiError::internal("empty JWKS"));
    }
    Ok(pem_by_kid)
}

async fn decoding_key_for_kid(client: &Client, kid: &str) -> Result<DecodingKey, ApiError> {
    let mutex = jwks_mutex();
    let mut guard = mutex.lock().await;
    let need_fetch = match guard.as_ref() {
        None => true,
        Some(c) => c.fetched_at.elapsed() > JWKS_CACHE_TTL || !c.pem_by_kid.contains_key(kid),
    };
    if need_fetch {
        let pem_by_kid = load_jwks(client).await?;
        *guard = Some(JwksCache {
            pem_by_kid,
            fetched_at: Instant::now(),
        });
    }
    let cache = guard.as_ref().ok_or_else(|| ApiError::internal("JWKS cache"))?;
    let pem = cache
        .pem_by_kid
        .get(kid)
        .ok_or_else(ApiError::unauthorized)?;
    DecodingKey::from_rsa_pem(pem).map_err(|_| ApiError::internal("invalid RSA PEM"))
}

/// Verifies a Google ID token and returns stable `sub` and verified email.
pub async fn verify_google_id_token(
    client: &Client,
    google_client_id: &str,
    id_token: &str,
) -> Result<GoogleIdTokenClaims, ApiError> {
    let header = decode_header(id_token).map_err(|_| ApiError::unauthorized())?;
    if header.alg != Algorithm::RS256 {
        return Err(ApiError::unauthorized());
    }
    let kid = header.kid.ok_or_else(ApiError::unauthorized)?;
    let key = decoding_key_for_kid(client, &kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[google_client_id]);
    validation.set_issuer(&["https://accounts.google.com"]);
    validation.validate_exp = true;
    validation.leeway = 60;
    validation.validate_aud = true;

    let token_data = decode::<GoogleIdTokenClaims>(id_token, &key, &validation)
        .map_err(|_| ApiError::unauthorized())?;

    let claims = token_data.claims;
    if !claims.email_verified {
        return Err(ApiError::bad_request(
            "Google account email must be verified",
        ));
    }
    if claims.email.trim().is_empty() {
        return Err(ApiError::unauthorized());
    }
    Ok(claims)
}
