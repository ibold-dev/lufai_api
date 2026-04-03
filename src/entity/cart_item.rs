//! SeaORM entity: `cart_items`

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "cart_items")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub cart_id: Uuid,
    pub product_id: Uuid,
    pub quantity: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::cart::Entity",
        from = "Column::CartId",
        to = "super::cart::Column::Id"
    )]
    Cart,
}

impl ActiveModelBehavior for ActiveModel {}
