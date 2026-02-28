mod auth_handler;
mod db;
mod errors;
mod jwt;
mod model;
mod sqs;
mod ssm;

use crate::auth_handler::{health_check, login, logout, refresh, register};
use crate::jwt::JwtKey;
use crate::model::AppState;
use crate::ssm::get_parameter;
use aws_config::BehaviorVersion;
use axum::routing::{get, post};
use axum::Router;
use lambda_http::{run, tracing, Error};
use std::env::{set_var, var};

#[tokio::main]
async fn main() -> Result<(), Error> {
    set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");
    tracing::init_default_subscriber();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    // use parameter store to get the secret value
    let ssm_client = aws_sdk_ssm::Client::new(&config);
    let (secret_value, queue_url) = tokio::join!(
        get_parameter(&ssm_client, "/korabo/prod", true),
        get_parameter(&ssm_client, "/korabo/prod/sqs", false),
    );

    let secret_value = secret_value?;
    let queue_url = queue_url?;

    // create sqs client
    let sqs_client = aws_sdk_sqs::Client::new(&config);

    // create dynamodb client
    let db = aws_sdk_dynamodb::Client::new(&config);

    let issuer = var("JWT_ISSUER").expect("JWT_ISSUER must be set");
    let audience = var("JWT_AUDIENCE").expect("JWT_AUDIENCE must be set");

    let jwt_keys = JwtKey::from_b64_pem(
        &secret_value,
        "0c54d5ee-prod-key".to_string(),
        issuer,   // issuer
        audience, // audience
    )?;

    let state = AppState {
        jwt_keys,
        db,
        queue_url,
        sqs: sqs_client,
    };

    let app = Router::new().nest(
        "/auth",
        Router::new()
            .route("/health", get(health_check))
            .route("/register", post(register))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/refresh", post(refresh))
            .with_state(state),
    );

    run(app).await
}
