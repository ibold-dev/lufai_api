use crate::http::error::ApiError;

use casbin::prelude::{CoreApi, Enforcer, MgmtApi};

const MODEL_PATH: &str = "casbin_model.conf";
const POLICY_PATH: &str = "casbin_policy.csv";

pub async fn create_enforcer() -> std::result::Result<Enforcer, ApiError> {
    let e = Enforcer::new(MODEL_PATH, POLICY_PATH).await
        .map_err(|e| ApiError::internal(format!("failed to create casbin enforcer: {e}")))?;
    Ok(e)
}

fn role_for_subject(subject: &str) -> Option<&'static str> {
    // JWT subjects follow `customer:{uuid}`, `seller:{uuid}`, `admin:{uuid}`.
    let prefix = subject.split_once(':').map(|(p, _)| p)?;
    match prefix {
        "customer" => Some("role:customer"),
        "seller" => Some("role:seller"),
        "admin" => Some("role:admin"),
        _ => None,
    }
}

pub async fn authorize_owned(
    enforcer: &mut Enforcer,
    sub: &str,
    obj: &str,
    act: &str,
    owner: &str,
) -> std::result::Result<bool, ApiError> {
    let Some(role) = role_for_subject(sub) else {
        return Err(ApiError::unauthorized());
    };

    let grouping = vec![sub.to_string(), role.to_string()];
    if !enforcer.has_grouping_policy(grouping.clone()) {
        enforcer
            .add_grouping_policy(grouping)
            .await
            .map_err(|e| ApiError::internal(format!("casbin add grouping failed: {e}")))?;
    }

    let allowed = enforcer
        .enforce((sub, obj, act, owner))
        .map_err(|e| ApiError::internal(format!("casbin enforce failed: {e}")))?;

    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn admin_can_approve_product_any_owner() {
        let mut enforcer = create_enforcer().await.expect("enforcer");

        let admin_sub = format!("admin:{}", Uuid::new_v4());
        let product_obj = format!("/products/{}", Uuid::new_v4());

        let allowed = authorize_owned(
            &mut enforcer,
            &admin_sub,
            &product_obj,
            "approve",
            "any",
        )
        .await
        .expect("authorize should succeed");

        assert!(allowed, "admin approve should be allowed");
    }

    #[tokio::test]
    async fn seller_delete_requires_ownership() {
        let mut enforcer = create_enforcer().await.expect("enforcer");

        let seller_1 = format!("seller:{}", Uuid::new_v4());
        let seller_2 = format!("seller:{}", Uuid::new_v4());
        let product_obj = format!("/products/{}", Uuid::new_v4());

        let allowed = authorize_owned(
            &mut enforcer,
            &seller_1,
            &product_obj,
            "delete",
            &seller_1,
        )
        .await
        .expect("authorize should succeed");

        assert!(allowed, "seller delete should be allowed for own products");

        let denied = authorize_owned(
            &mut enforcer,
            &seller_1,
            &product_obj,
            "delete",
            &seller_2,
        )
        .await
        .expect("authorize should succeed");

        assert!(!denied, "seller delete should be denied for other owners");
    }
}

