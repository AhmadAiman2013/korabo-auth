use crate::errors::AppError;
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Header};
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Serialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
}

#[derive(Debug, Clone)]
pub struct JwtKey {
    pub encoding_key: EncodingKey,
    pub kid: String,
    pub issuer: String,
    pub audience: String,
}

impl JwtKey {
    pub fn from_b64_pem(
        b64: &str,
        kid: String,
        issuer: String,
        audience: String,
    ) -> Result<Self, AppError> {
        let pem = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let encoding_key = EncodingKey::from_rsa_pem(&pem)?;
        Ok(Self {
            encoding_key,
            kid,
            issuer,
            audience,
        })
    }
}

pub fn issue_access_token(key: &JwtKey, user_id: &str, email: &str) -> Result<String, AppError> {
    let now = OffsetDateTime::now_utc();

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        iat: now.unix_timestamp(),
        exp: (now + Duration::minutes(15)).unix_timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        iss: key.issuer.clone(),
        aud: key.audience.clone(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());

    encode(&header, &claims, &key.encoding_key).map_err(AppError::JwtError)
}
