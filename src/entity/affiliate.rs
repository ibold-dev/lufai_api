//! SeaORM entity: `affiliates`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "affiliates")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Normalized uppercase; unique. Length 1–32 (see migration `CHECK`).
    #[sea_orm(unique)]
    pub code: String,
    /// Set for affiliates that can sign in; unique when present.
    pub email: Option<String>,
    pub login_code_hash: Option<String>,
    pub login_revoked_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
