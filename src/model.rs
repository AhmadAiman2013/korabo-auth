use aws_sdk_dynamodb::Client;

#[derive(Clone)]
pub struct AppState {
    pub jwt_secret: String,
    pub db: Client,
}
