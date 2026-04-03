//! SeaORM entity: `promotions`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "promotions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `None` = platform-wide campaign (all listed products).
    pub seller_id: Option<Uuid>,
    pub name: String,
    pub status: String,
    pub starts_at: DateTimeUtc,
    pub ends_at: DateTimeUtc,
    pub discount_kind: String,
    pub discount_percent: Option<i32>,
    pub discount_fixed_cents: Option<i64>,
    pub priority: i32,
    /// When `None`, line inherits product rules. When set, overrides for discounted lines.
    #[sea_orm(column_type = "Json", nullable)]
    pub allowed_payment_methods: Option<Vec<String>>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
