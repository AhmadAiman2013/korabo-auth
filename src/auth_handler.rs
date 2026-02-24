use crate::errors::{AppError, DynamodbError};
use crate::jwt::issue_access_token;
use crate::model::AppState;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use aws_sdk_dynamodb::types::AttributeValue;
use axum::extract::State;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

// GET /auth/health
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

// POST /auth/register
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
        created_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
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

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// POST /auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), AppError> {
    let LoginRequest { email, password } = payload;

    // 1. look up user by email via GSI
    let result = state
        .db
        .query()
        .table_name("korabo_auth")
        .index_name("email-index")
        .key_condition_expression("email = :email")
        .expression_attribute_values(":email", AttributeValue::S(email.clone()))
        .send()
        .await
        .map_err(DynamodbError::QueryError)?;

    let items = result.items();

    let profile = items
        .iter()
        .find(|item| {
            item.get("SK")
                .and_then(|v| v.as_s().ok())
                .map(|s| s == "PROFILE")
                .unwrap_or(false)
        })
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".to_string()))?;

    // 2. Extract user_id and hashed_password
    let user_id = profile
        .get("PK")
        .and_then(|v| v.as_s().ok())
        .map(|s| s.trim_start_matches("USER#").to_string())
        .ok_or_else(|| AppError::InternalServerError("missing PK".to_string()))?;

    let hashed_password = profile
        .get("hashed_password")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| AppError::InternalServerError("missing hashed_password".to_string()))?
        .to_string();

    // 3. Verify password
    let password_valid = tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&hashed_password)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        Ok::<bool, AppError>(
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok(),
        )
    })
    .await
    .map_err(|e| AppError::InternalServerError(e.to_string()))??;

    if !password_valid {
        return Err(AppError::Unauthorized("invalid credentials".to_string()));
    }

    // 4. Issue access token (15 min)
    let access_token = issue_access_token(&state.jwt_keys, &user_id, &email)?;

    // 5. Build refresh token
    //    token_id  → SK suffix for fast DB lookup
    //    raw_token → random bytes, sent plain in cookie, never stored
    //    token_hash → sha256(raw_token), stored in DB for verification
    let token_id = uuid::Uuid::new_v4().to_string();
    let raw_token = {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(&bytes)
    };
    let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
    let refresh_expired_at = OffsetDateTime::now_utc() + Duration::days(1);

    // 6. Store only the hash
    state
        .db
        .put_item()
        .table_name("korabo_auth")
        .item("PK", AttributeValue::S(format!("USER#{}", user_id)))
        .item(
            "SK",
            AttributeValue::S(format!("REFRESH_TOKEN#{}", token_id)),
        )
        .item("token_hash", AttributeValue::S(token_hash))
        .item(
            "expires_at_iso",
            AttributeValue::S(
                refresh_expired_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
            ),
        )
        .item(
            "expires_at",
            AttributeValue::N(refresh_expired_at.unix_timestamp().to_string()),
        )
        .send()
        .await
        .map_err(DynamodbError::PutItemError)?;

    // 7. Cookie value = <user_id>.<token_id>.<raw_token>
    let cookie_value = format!("{}.{}.{}", user_id, token_id, raw_token);

    let cookie = Cookie::build(("refresh_token", cookie_value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::days(1))
        .path("/auth/refresh")
        .build();

    let jar = CookieJar::new().add(cookie);

    Ok((
        jar,
        Json(json!({
            "code": "korabo_auth_200",
            "status": "login successful",
            "access_token": access_token,
            "expires_in": 900
        })),
    ))
}
