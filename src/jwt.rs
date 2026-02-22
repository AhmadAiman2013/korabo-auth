use crate::errors::AppError;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::{encode, Header};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug)]
pub struct JwtKey {
    pub decoding_key: EncodingKey,
}

pub fn issue_access_token(key: &JwtKey, user_id: &str, email: &str) -> Result<String, AppError> {
    let now = chrono::Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        iat: now.timestamp(),
        exp: (now + chrono::Duration::minutes(15)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
    };

    encode(&Header::default(), &claims, &key.decoding_key).map_err(AppError::JwtError)
}
