//! Groups of users, used in `group` access rules. Admins manage them; members can list them.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    app::AppState,
    audit::Action,
    auth::users::CurrentUser,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    util::now,
};

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub members: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct GroupInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Members {
    pub user_ids: Vec<i64>,
}

fn require_admin(user: &CurrentUser) -> AppResult<()> {
    if !user.is_admin() {
        return Err(AppError::Forbidden("admins only".into()));
    }
    Ok(())
}

fn clean(input: GroupInput) -> AppResult<GroupInput> {
    let name = input.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(AppError::BadRequest("group name must be 1-80 characters".into()));
    }
    Ok(GroupInput {
        name,
        description: input.description.trim().chars().take(500).collect(),
    })
}

const GROUP_SELECT: &str =
    "SELECT g.id, g.name, g.description, (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.id) AS members FROM groups g";

async fn one(state: &AppState, id: i64) -> AppResult<Group> {
    sqlx::query_as(&format!("{GROUP_SELECT} WHERE g.id = ?"))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)
}

/// All groups (any signed-in user, for access rules).
#[utoipa::path(get, path = "/groups", tag = "org", operation_id = "groups_list", responses((status = 200, body = Vec<Group>)))]
async fn list(State(state): State<AppState>, _user: CurrentUser) -> AppResult<Json<Vec<Group>>> {
    Ok(Json(
        sqlx::query_as(&format!("{GROUP_SELECT} ORDER BY lower(g.name)"))
            .fetch_all(&state.db)
            .await?,
    ))
}

/// Create a group (admins).
#[utoipa::path(post, path = "/groups", tag = "org", operation_id = "groups_create", request_body = GroupInput,
    responses((status = 201, body = Group), (status = 409, body = crate::error::ErrorBody)))]
async fn create(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<GroupInput>,
) -> AppResult<(StatusCode, Json<Group>)> {
    require_admin(&user)?;
    let g = clean(req)?;
    let res = sqlx::query_as::<_, (i64,)>("INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?) RETURNING id")
        .bind(&g.name)
        .bind(&g.description)
        .bind(now())
        .fetch_one(&state.db)
        .await;
    let id = match res {
        Ok((id,)) => id,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => return Err(AppError::Conflict("a group with that name exists".into())),
        Err(e) => return Err(e.into()),
    };
    state
        .audit
        .record(
            user.event(Action::GroupCreated)
                .client(&client)
                .target("group", id.to_string(), Some(g.name)),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(one(&state, id).await?)))
}

/// Rename or describe a group (admins).
#[utoipa::path(patch, path = "/groups/{id}", tag = "org", operation_id = "groups_update", params(("id" = i64, Path)), request_body = GroupInput,
    responses((status = 200, body = Group)))]
async fn update(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<i64>,
    Json(req): Json<GroupInput>,
) -> AppResult<Json<Group>> {
    require_admin(&user)?;
    one(&state, id).await?;
    let g = clean(req)?;
    sqlx::query("UPDATE groups SET name = ?, description = ? WHERE id = ?")
        .bind(&g.name)
        .bind(&g.description)
        .bind(id)
        .execute(&state.db)
        .await?;
    state
        .audit
        .record(
            user.event(Action::GroupUpdated)
                .client(&client)
                .target("group", id.to_string(), Some(g.name)),
        )
        .await?;
    Ok(Json(one(&state, id).await?))
}

/// Delete a group (admins). Shares that named it simply stop matching it.
#[utoipa::path(delete, path = "/groups/{id}", tag = "org", operation_id = "groups_delete", params(("id" = i64, Path)), responses((status = 204)))]
async fn delete(State(state): State<AppState>, client: ClientInfo, user: CurrentUser, Path(id): Path<i64>) -> AppResult<StatusCode> {
    require_admin(&user)?;
    let g = one(&state, id).await?;
    sqlx::query("DELETE FROM groups WHERE id = ?").bind(id).execute(&state.db).await?;
    state
        .audit
        .record(
            user.event(Action::GroupDeleted)
                .client(&client)
                .target("group", id.to_string(), Some(g.name)),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A group's member ids.
#[utoipa::path(get, path = "/groups/{id}/members", tag = "org", operation_id = "groups_members", params(("id" = i64, Path)),
    responses((status = 200, body = Members)))]
async fn members(State(state): State<AppState>, _user: CurrentUser, Path(id): Path<i64>) -> AppResult<Json<Members>> {
    one(&state, id).await?;
    let ids: Vec<(i64,)> = sqlx::query_as("SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id")
        .bind(id)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(Members {
        user_ids: ids.into_iter().map(|r| r.0).collect(),
    }))
}

/// Replace a group's members (admins).
#[utoipa::path(put, path = "/groups/{id}/members", tag = "org", operation_id = "groups_set_members", params(("id" = i64, Path)), request_body = Members,
    responses((status = 200, body = Group)))]
async fn set_members(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<i64>,
    Json(req): Json<Members>,
) -> AppResult<Json<Group>> {
    require_admin(&user)?;
    let g = one(&state, id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM group_members WHERE group_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for u in &req.user_ids {
        let res = sqlx::query("INSERT INTO group_members (group_id, user_id) SELECT ?, id FROM users WHERE id = ?")
            .bind(id)
            .bind(u)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::BadRequest(format!("unknown user {u}")));
        }
    }
    tx.commit().await?;
    state
        .audit
        .record(
            user.event(Action::GroupUpdated)
                .client(&client)
                .target("group", id.to_string(), Some(g.name))
                .detail("members", &req.user_ids),
        )
        .await?;
    Ok(Json(one(&state, id).await?))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(update, delete))
        .routes(routes!(members, set_members))
}
