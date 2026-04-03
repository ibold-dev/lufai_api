//! Resolve best active promotion per order line (platform-wide or seller-scoped).

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::entity::{product, promotion, promotion_product};
use crate::http::error::ApiError;
use crate::payments::methods;

#[derive(Debug, Clone)]
pub struct PricedLine {
    pub product_id: Uuid,
    pub quantity: i32,
    pub list_unit_price_cents: i64,
    pub unit_price_cents: i64,
    pub promotion_id: Option<Uuid>,
    /// Effective allowed payment methods for this line (product defaults or promo override).
    pub allowed_payment_methods: Vec<String>,
}

fn promo_is_live(p: &promotion::Model, now: chrono::DateTime<Utc>) -> bool {
    p.status == "active" && now >= p.starts_at && now <= p.ends_at
}

fn eligible(pr: &promotion::Model, product_seller_id: Uuid) -> bool {
    pr.seller_id.is_none() || pr.seller_id == Some(product_seller_id)
}

fn apply_discount(list: i64, pr: &promotion::Model) -> i64 {
    match pr.discount_kind.as_str() {
        "percent" => {
            let pct = pr.discount_percent.unwrap_or(0) as i64;
            let off = list.saturating_mul(pct) / 100;
            (list - off).max(0)
        }
        "fixed_unit" => {
            let fixed = pr.discount_fixed_cents.unwrap_or(0);
            (list - fixed).max(0)
        }
        _ => list,
    }
}

fn pick_best<'a>(
    promo_refs: impl Iterator<Item = &'a promotion::Model>,
    product_seller_id: Uuid,
) -> Option<&'a promotion::Model> {
    promo_refs
        .filter(|p| eligible(p, product_seller_id))
        .max_by_key(|p| (p.priority, p.id))
}

/// Computes list and discounted unit prices for each line. Only **`approved`** products are accepted.
pub async fn price_order_lines(
    db: &DatabaseConnection,
    items: &[(Uuid, i32)],
) -> Result<Vec<PricedLine>, ApiError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let unique_ids: Vec<Uuid> = items.iter().map(|(id, _)| *id).collect::<HashSet<_>>().into_iter().collect();

    let products = product::Entity::find()
        .filter(product::Column::Id.is_in(unique_ids.clone()))
        .filter(product::Column::Status.eq("approved"))
        .all(db)
        .await?;

    if products.len() != unique_ids.len() {
        return Err(ApiError::bad_request("product not available"));
    }

    let product_map: HashMap<Uuid, product::Model> =
        products.into_iter().map(|p| (p.id, p)).collect();

    let pp_rows = promotion_product::Entity::find()
        .filter(promotion_product::Column::ProductId.is_in(unique_ids.clone()))
        .all(db)
        .await?;

    let promo_id_set: HashSet<Uuid> = pp_rows.iter().map(|r| r.promotion_id).collect();
    let promo_ids: Vec<Uuid> = promo_id_set.into_iter().collect();

    let promos = if promo_ids.is_empty() {
        Vec::new()
    } else {
        promotion::Entity::find()
            .filter(promotion::Column::Id.is_in(promo_ids))
            .all(db)
            .await?
    };

    let promo_map: HashMap<Uuid, promotion::Model> =
        promos.into_iter().map(|p| (p.id, p)).collect();
    let now = Utc::now();

    let mut product_to_promo_ids: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for row in pp_rows {
        if let Some(pr) = promo_map.get(&row.promotion_id) {
            if promo_is_live(pr, now) {
                product_to_promo_ids
                    .entry(row.product_id)
                    .or_default()
                    .push(row.promotion_id);
            }
        }
    }

    let mut out = Vec::with_capacity(items.len());
    for &(product_id, quantity) in items {
        let p = product_map
            .get(&product_id)
            .ok_or_else(|| ApiError::bad_request("product not available"))?;
        let list = p.price_cents;

        let best = product_to_promo_ids
            .get(&product_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|pid| promo_map.get(pid))
                    .filter(|pr| promo_is_live(pr, now))
            })
            .and_then(|it| pick_best(it, p.seller_id));

        let (unit_price_cents, promotion_id) = match best {
            Some(pr) => (apply_discount(list, pr), Some(pr.id)),
            None => (list, None),
        };

        let allowed_payment_methods =
            methods::line_effective_methods(p, best);

        out.push(PricedLine {
            product_id,
            quantity,
            list_unit_price_cents: list,
            unit_price_cents,
            promotion_id,
            allowed_payment_methods,
        });
    }

    Ok(out)
}
