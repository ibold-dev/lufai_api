//! SeaORM migrations: schema changes live here (`sea-orm-cli migrate generate` for new revisions).

mod m20260403000000_init;
mod m20260403000001_customer_google_auth;
mod m20260403000002_full_names;
mod m20260403000003_affiliates;
mod m20260403000004_carts;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260403000000_init::Migration),
            Box::new(m20260403000001_customer_google_auth::Migration),
            Box::new(m20260403000002_full_names::Migration),
            Box::new(m20260403000003_affiliates::Migration),
            Box::new(m20260403000004_carts::Migration),
        ]
    }
}
