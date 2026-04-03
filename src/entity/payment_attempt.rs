//! SeaORM entity: `payment_attempts`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "payment_attempts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub order_id: Uuid,
    pub provider: String,
    #[sea_orm(unique)]
    pub paystack_reference: String,
    pub amount_cents: i64,
    pub currency: String,
    pub status: String,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub raw_payload: Option<Json>,
    pub paid_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
