//! SeaORM entity: `products`

use sea_orm::entity::prelude::*;
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "products")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub seller_id: Uuid,
    pub title: String,
    pub description: String,
    pub price_cents: i64,
    pub currency: String,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub dimensions: Option<Json>,
    /// When `None`, all methods (`electronic`, `cash_on_delivery`, `installment`) apply.
    /// Stored as JSON array in `jsonb` (not `text[]`).
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub allowed_payment_methods: Option<JsonValue>,
    pub status: String,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
