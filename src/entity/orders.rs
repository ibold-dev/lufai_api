//! SeaORM entity: `orders`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "orders")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub customer_id: Uuid,
    pub status: String,
    pub currency: String,
    pub subtotal_cents: i64,
    pub shipping_cents: i64,
    pub tax_cents: i64,
    pub total_cents: i64,
    /// Intersection of allowed methods for all lines at checkout (snapshot).
    #[sea_orm(column_type = "Json")]
    pub allowed_payment_methods: Vec<String>,
    /// Set when customer chooses COD, installment, or Paystack (electronic).
    pub payment_channel: Option<String>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub installment_plan: Option<Json>,
    #[sea_orm(column_type = "JsonBinary")]
    pub delivery_address: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
