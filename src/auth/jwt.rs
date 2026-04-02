use crate::http::error::ApiError;
use jsonwebtoken::{encode, decode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn create_access_token(
    subject: &str,
    secret: &str,
    issuer: &str,
    ttl_secs: i64,
) -> Result<String, ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::internal(format!("clock error: {e}")))?;
    let iat = now.as_secs() as i64;
    let exp = iat + ttl_secs;

    let claims = JwtClaims {
        sub: subject.to_string(),
        iss: issuer.to_string(),
        iat,
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal(format!("jwt encode failed: {e}")))
}

pub fn decode_access_token(
    token: &str,
    secret: &str,
    expected_issuer: &str,
) -> Result<JwtClaims, ApiError> {
    let validation = Validation::default();
    let token_data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_e| ApiError::unauthorized())?;

    if token_data.claims.iss != expected_issuer {
        return Err(ApiError::unauthorized());
    }

    Ok(token_data.claims)
}

