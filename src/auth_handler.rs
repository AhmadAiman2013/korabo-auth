use crate::errors::{AppError, DynamodbError};
use crate::model::AppState;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use aws_sdk_dynamodb::types::AttributeValue;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub async fn health_check() -> Json<Value> {
    let health = true;
    match health {
        true => Json(json!({ "status": "healthy" })),
        false => Json(json!({ "status": "unhealthy" })),
    }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone)]
struct UserProfile {
    user_id: String,
    email: String,
    hashed_password: String,
    created_at: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    let RegisterRequest { email, password } = payload;

    let existing = state
        .db
        .query()
        .table_name("korabo_auth")
        .index_name("email-index")
        .key_condition_expression("email = :email")
        .expression_attribute_values(":email", AttributeValue::S(email.clone()))
        .send()
        .await
        .map_err(DynamodbError::QueryError)?;

    if existing.count > 0 {
        return Ok(Json(json!({
            "code": "korabo_auth_101",
            "status": "already registered"
        })));
    }

    // Hash the password
    let hashed_password = hash_password(&password).await?;

    let user = UserProfile {
        user_id: uuid::Uuid::new_v4().to_string(),
        email,
        hashed_password,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let _ = state
        .db
        .put_item()
        .table_name("korabo_auth")
        .item("PK", AttributeValue::S(format!("USER#{}", user.user_id)))
        .item("SK", AttributeValue::S("PROFILE".to_string()))
        .item("email", AttributeValue::S(user.email))
        .item("hashed_password", AttributeValue::S(user.hashed_password))
        .item("created_at", AttributeValue::S(user.created_at))
        .send()
        .await
        .map_err(DynamodbError::PutItemError)?;

    Ok(Json(json!({
        "code": "korabo_auth_100",
        "status": "registered successfully"
    })))
}

async fn hash_password(password: &str) -> Result<String, AppError> {
    let password = password.to_owned();
    // Implement password hashing logic here using argon2
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    })
    .await
    .map_err(|e| AppError::InternalServerError(e.to_string()))?
}
