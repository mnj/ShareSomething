//! Team mode: org policies, users, groups and invites.

pub mod admin;
pub mod groups;
pub mod settings;

use utoipa_axum::router::OpenApiRouter;

use crate::app::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    settings::router().merge(admin::router()).merge(groups::router())
}
