use crate::http::error::ApiError;
use crate::http::limits::MAX_PASSWORD_BYTES;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    if password.len() < 8 {
        return Err(ApiError::bad_request(
            "password must be at least 8 characters".to_string(),
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(ApiError::bad_request("password is too long".to_string()));
    }

    let salt = SaltString::generate(rand_core::OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| ApiError::internal(format!("password hash failed: {e}")))
}

pub fn verify_password(password_hash: &str, password: &str) -> Result<bool, ApiError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|e| {
            ApiError::internal(format!("invalid password hash: {e}"))
        })?;

    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password_rejects_too_short_password() {
        let err = hash_password("short").unwrap_err();
        match err {
            ApiError::BadRequest(_) => {}
            _ => panic!("expected bad_request for short password"),
        }
    }

    #[test]
    fn password_roundtrip_verification() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).expect("hash should succeed");

        assert!(
            verify_password(&hash, password).expect("verify should succeed"),
            "verification should succeed for the original password"
        );
        assert!(
            !verify_password(&hash, "wrong password").expect("verify should succeed"),
            "verification should fail for a different password"
        );
    }
}

