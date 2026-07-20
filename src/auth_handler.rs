use crate::errors::{AppError, DynamodbError};
use crate::jwt::issue_access_token;
use crate::model::{AppState, UserRegisteredEvent};
use crate::sqs::publish_user_registered;
use crate::totp::verify_totp_code;
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
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use totp_rs::{Algorithm, Secret, TOTP};

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

    if find_profile_by_email(&state.db, &email).await?.is_some() {
        return Ok(Json(json!({
            "code": "korabo_auth_101",
            "status": "user already registered"
        })));
    }

    // totp check
    let pending_item = get_pending_totp_item(&state.db, &email).await?;

    let verified = pending_item
        .get("verified")
        .and_then(|v| v.as_bool().ok())
        .copied()
        .unwrap_or(false);

    if !verified {
        return Err(AppError::InternalServerError(
            "totp not verified".to_string(),
        ));
    }

    let totp_secret = pending_item
        .get("secret")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| AppError::InternalServerError("missing secret".to_string()))?
        .to_string();

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
        .item(
            "PK",
            AttributeValue::S(format!("USER#{}", user.user_id.clone())),
        )
        .item("SK", AttributeValue::S("PROFILE".to_string()))
        .item("email", AttributeValue::S(user.email.clone()))
        .item("hashed_password", AttributeValue::S(user.hashed_password))
        .item("created_at", AttributeValue::S(user.created_at))
        .item("totp_secret", AttributeValue::S(totp_secret))
        .send()
        .await
        .map_err(DynamodbError::PutItemError)?;

    publish_user_registered(
        &state.sqs,
        &state.queue_url,
        &UserRegisteredEvent {
            user_id: user.user_id,
            email: user.email,
        },
    )
    .await?;

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

fn build_auth_response(code: &str, status: &str, access_token: &str) -> Json<Value> {
    Json(json!({
        "code": code,
        "status": status,
        "access_token": access_token,
        "expires_in": 900
    }))
}

// POST /auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), AppError> {
    let LoginRequest { email, password } = payload;

    // 1. look up user by email via GSI
    let profile = find_profile_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".to_string()))?;

    // 2. Extract user_id and hashed_password
    let user_id = extract_user_id_from_pk(&profile)?;

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
    let access_token = issue_access_token(&state.jwt_keys, &user_id)?;

    // 5. Return response
    let cookie = mint_new_credentials(&state.db, &user_id).await?;

    let jar = CookieJar::new().add(cookie);

    Ok((
        jar,
        build_auth_response("korabo_auth_200", "login successful", &access_token),
    ))
}

// POST /auth/refresh
pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<Value>), AppError> {
    // 1. Pull and parse cookie
    let cookie = jar
        .get("refresh_token")
        .ok_or_else(|| AppError::Unauthorized("no refresh token".to_string()))?;

    let parts: Vec<&str> = cookie.value().splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized("invalid cookie".to_string()));
    }
    let (user_id, token_id, raw_token) = (parts[0], parts[1], parts[2]);

    // 2. Fetch the stored record from DynamoDB
    let result = state
        .db
        .get_item()
        .table_name("korabo_auth")
        .key("PK", AttributeValue::S(format!("USER#{}", user_id)))
        .key(
            "SK",
            AttributeValue::S(format!("REFRESH_TOKEN#{}", token_id)),
        )
        .send()
        .await
        .map_err(DynamodbError::GetItemError)?;

    let record = result
        .item()
        .ok_or_else(|| AppError::Unauthorized("no refresh token found".to_string()))?;

    // 3. hash comparison
    let stored_hash = record
        .get("token_hash")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| AppError::InternalServerError("missing token hash".to_string()))?;

    let incoming_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

    if stored_hash != &incoming_hash {
        return Err(AppError::Unauthorized("invalid refresh token".to_string()));
    }

    // 4. Issue access token (15 min)
    let access_token = issue_access_token(&state.jwt_keys, &user_id)?;

    // 5. Return response
    let cookie = mint_new_credentials(&state.db, &user_id).await?;

    let jar = CookieJar::new().add(cookie);

    Ok((
        jar,
        build_auth_response("korabo_auth_201", "refresh successful", &access_token),
    ))
}

// POST /auth/logout
pub async fn logout(jar: CookieJar) -> Result<(CookieJar, Json<Value>), AppError> {
    let expired_cookie = build_refresh_token_cookie("", Duration::ZERO);
    let jar = jar.remove(expired_cookie);

    Ok((
        jar,
        Json(json!({
            "code": "korabo_auth_300",
            "status": "logged out"
        })),
    ))
}

fn extract_user_id_from_pk(profile: &HashMap<String, AttributeValue>) -> Result<String, AppError> {
    profile
        .get("PK")
        .and_then(|v| v.as_s().ok())
        .map(|s| s.trim_start_matches("USER#").to_string())
        .ok_or_else(|| AppError::InternalServerError("missing PK".to_string()))
}

async fn get_pending_totp_item(
    db: &aws_sdk_dynamodb::Client,
    email: &str,
) -> Result<HashMap<String, AttributeValue>, AppError> {
    let result = db
        .get_item()
        .table_name("korabo_auth")
        .key("PK", AttributeValue::S(format!("PENDING#{}", email)))
        .key("SK", AttributeValue::S("TOTP".to_string()))
        .send()
        .await
        .map_err(DynamodbError::GetItemError)?;

    result
        .item()
        .cloned()
        .ok_or_else(|| AppError::NotFound("no pending totp setup".to_string()))
}

async fn find_profile_by_email(
    db: &aws_sdk_dynamodb::Client,
    email: &str,
) -> Result<Option<HashMap<String, AttributeValue>>, AppError> {
    let result = db
        .query()
        .table_name("korabo_auth")
        .index_name("email-index")
        .key_condition_expression("email = :email")
        .expression_attribute_values(":email", AttributeValue::S(email.to_string()))
        .send()
        .await
        .map_err(DynamodbError::QueryError)?;

    let profile = result
        .items()
        .iter()
        .find(|item| {
            item.get("SK")
                .and_then(|v| v.as_s().ok())
                .map(|s| s == "PROFILE")
                .unwrap_or(false)
        })
        .cloned();

    Ok(profile)
}

async fn mint_new_credentials(
    db: &aws_sdk_dynamodb::Client,
    user_id: &str,
) -> Result<Cookie<'static>, AppError> {
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

    _ = db
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

    let cookie = build_refresh_token_cookie(&cookie_value, Duration::days(1));

    Ok(cookie)
}

fn build_refresh_token_cookie(value: &str, max_age: Duration) -> Cookie<'static> {
    Cookie::build(("refresh_token", value.to_string()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .max_age(max_age)
        .path("/auth")
        .build()
}

// TOTP flow

#[derive(Deserialize)]
pub struct TotpSetupRequest {
    pub email: String,
}

// POST /auth/totp/setup
pub async fn totp_setup(
    State(state): State<AppState>,
    Json(payload): Json<TotpSetupRequest>,
) -> Result<Json<Value>, AppError> {
    let TotpSetupRequest { email } = payload;

    if find_profile_by_email(&state.db, &email).await?.is_some() {
        return Err(AppError::InternalServerError(
            "email already registered".to_string(),
        ));
    }

    let secret = Secret::generate_secret().to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.clone()).to_bytes().unwrap(),
        Some("Korabo".to_string()),
        email.clone(),
    )
    .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(15);

    state
        .db
        .put_item()
        .table_name("korabo_auth")
        .item("PK", AttributeValue::S(format!("PENDING#{}", email)))
        .item("SK", AttributeValue::S("TOTP".to_string()))
        .item("secret", AttributeValue::S(secret))
        .item("verified", AttributeValue::Bool(false))
        .item(
            "expires_at",
            AttributeValue::N(expires_at.unix_timestamp().to_string()),
        )
        .send()
        .await
        .map_err(DynamodbError::PutItemError)?;

    Ok(Json(json!({
        "code": "korabo_auth_400",
        "otpauth_url": totp.get_url()
    })))
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    pub email: String,
    pub code: String,
}

// POST /auth/totp/verify-setup
pub async fn totp_verify_setup(
    State(state): State<AppState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<Value>, AppError> {
    let TotpVerifyRequest { email, code } = payload;

    let item = get_pending_totp_item(&state.db, &email).await?;

    let secret = item
        .get("secret")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| AppError::InternalServerError("missing secret".to_string()))?;

    if !verify_totp_code(secret, &code)? {
        return Err(AppError::Unauthorized("invalid code".to_string()));
    }

    state
        .db
        .update_item()
        .table_name("korabo_auth")
        .key("PK", AttributeValue::S(format!("PENDING#{}", email)))
        .key("SK", AttributeValue::S("TOTP".to_string()))
        .update_expression("SET verified = :v")
        .expression_attribute_values(":v", AttributeValue::Bool(true))
        .send()
        .await
        .map_err(DynamodbError::UpdateItemError)?;

    Ok(Json(
        json!({ "code": "korabo_auth_401", "status": "verified" }),
    ))
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    pub code: String,
    pub new_password: String,
}

// POST /auth/forgot-password
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    let ForgotPasswordRequest {
        email,
        code,
        new_password,
    } = payload;

    let profile = find_profile_by_email(&state.db, &email)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid email".to_string()))?;

    let user_id = extract_user_id_from_pk(&profile)?;

    let secret = profile
        .get("totp_secret")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| AppError::Unauthorized("2fa not set up".to_string()))?;

    if !verify_totp_code(secret, &code)? {
        return Err(AppError::Unauthorized("invalid code".to_string()));
    }

    let hashed_password = hash_password(&new_password).await?;

    state
        .db
        .update_item()
        .table_name("korabo_auth")
        .key("PK", AttributeValue::S(format!("USER#{}", user_id)))
        .key("SK", AttributeValue::S("PROFILE".to_string()))
        .update_expression("SET hashed_password = :h")
        .expression_attribute_values(":h", AttributeValue::S(hashed_password))
        .send()
        .await
        .map_err(DynamodbError::UpdateItemError)?;

    Ok(Json(
        json!({ "code": "korabo_auth_402", "status": "password updated" }),
    ))
}
