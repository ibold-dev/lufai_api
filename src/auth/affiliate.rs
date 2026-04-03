//! Resolve affiliate referral codes at customer signup (insert only).

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::{
    entity::affiliate,
    http::error::ApiError,
    http::limits::MAX_AFFILIATE_CODE_LEN,
};

/// Normalize user input for lookup; DB stores uppercase codes.
pub fn normalize_affiliate_code(input: &str) -> String {
    input.trim().to_ascii_uppercase()
}

/// Returns `None` if no code was provided. Errors if a non-empty code is unknown or too long.
pub async fn resolve_affiliate_id_for_signup(
    db: &DatabaseConnection,
    code_raw: Option<&str>,
) -> Result<Option<Uuid>, ApiError> {
    let Some(raw) = code_raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_AFFILIATE_CODE_LEN {
        return Err(ApiError::bad_request("affiliate code is too long"));
    }
    let code = normalize_affiliate_code(trimmed);
    if code.is_empty() {
        return Ok(None);
    }
    let row = affiliate::Entity::find()
        .filter(affiliate::Column::Code.eq(&code))
        .one(db)
        .await?;
    match row {
        Some(a) => Ok(Some(a.id)),
        None => Err(ApiError::bad_request("unknown affiliate code")),
    }
}
