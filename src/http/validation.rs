use serde_json::Value;

use crate::http::error::ApiError;
use crate::http::limits::MAX_JSON_VALUE_BYTES;

/// Rejects JSON values whose serialized size exceeds [`MAX_JSON_VALUE_BYTES`].
pub fn check_json_value_size(label: &str, v: &Value) -> Result<(), ApiError> {
    let n = serde_json::to_vec(v)
        .map_err(|_| ApiError::bad_request(format!("invalid {label}")))?
        .len();
    if n > MAX_JSON_VALUE_BYTES {
        return Err(ApiError::bad_request(format!(
            "{label} exceeds maximum allowed size"
        )));
    }
    Ok(())
}

pub fn check_optional_json_value_size(
    label: &str,
    v: &Option<Value>,
) -> Result<(), ApiError> {
    if let Some(inner) = v {
        check_json_value_size(label, inner)?;
    }
    Ok(())
}
