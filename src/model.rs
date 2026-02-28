use crate::jwt::JwtKey;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_sqs::Client;
use serde::Serialize;

#[derive(Clone)]
pub struct AppState {
    pub jwt_keys: JwtKey,
    pub db: DynamoClient,
    pub queue_url: String,
    pub sqs: Client,
}

#[derive(Serialize)]
pub struct UserRegisteredEvent {
    pub user_id: String,
    pub email: String,
}
