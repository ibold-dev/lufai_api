//! SeaORM entity: `sellers`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sellers")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub email: String,
    pub full_name: String,
    /// Legacy password login; optional when using admin-issued login codes.
    pub password_hash: Option<String>,
    /// Argon2 hash of the current login code (admin-issued; shown once).
    pub login_code_hash: Option<String>,
    /// When set, seller cannot sign in with the login code (until rotated).
    pub login_revoked_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
