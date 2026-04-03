use crate::http::error::ApiError;
use crate::http::limits::MIN_JWT_SECRET_BYTES;
use sea_orm::DatabaseConnection;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub access_token_ttl_secs: i64,
}

impl AppState {
    pub fn from_db(db: DatabaseConnection) -> Result<Self, ApiError> {
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| ApiError::internal("JWT_SECRET is not set".to_string()))?;
        if jwt_secret.len() < MIN_JWT_SECRET_BYTES {
            return Err(ApiError::internal(format!(
                "JWT_SECRET must be at least {MIN_JWT_SECRET_BYTES} bytes"
            )));
        }

        let jwt_issuer = std::env::var("JWT_ISSUER").unwrap_or_else(|_| "lufai_api".to_string());

        let access_token_ttl_secs = std::env::var("JWT_ACCESS_TOKEN_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86_400);

        Ok(Self {
            db,
            jwt_secret,
            jwt_issuer,
            access_token_ttl_secs,
        })
    }
}

