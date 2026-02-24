use crate::jwt::JwtKey;
use aws_sdk_dynamodb::Client;

#[derive(Clone)]
pub struct AppState {
    pub jwt_keys: JwtKey,
    pub db: Client,
}
