//! SeaORM entity: `customers`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "customers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub email: String,
    /// Set when the account uses email/password. `None` for Google-only sign-in.
    pub password_hash: Option<String>,
    /// Google `sub` claim; unique per Google account when present.
    #[sea_orm(unique)]
    pub google_sub: Option<String>,
    pub full_name: String,
    pub phone: Option<String>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub address: Option<Json>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
