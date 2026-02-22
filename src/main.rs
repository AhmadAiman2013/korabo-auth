mod auth_handler;
mod db;
mod errors;
mod jwt;
mod model;
mod ssm;

use crate::auth_handler::{health_check, register};
use crate::model::AppState;
use crate::ssm::get_secret_value;
use aws_config::BehaviorVersion;
use axum::routing::{get, post};
use axum::Router;
use lambda_http::{run, tracing, Error};
use std::env::set_var;

#[tokio::main]
async fn main() -> Result<(), Error> {
    set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");
    tracing::init_default_subscriber();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    // use parameter store to get the secret value
    let ssm_client = aws_sdk_ssm::Client::new(&config);
    let secret_name = "/korabo/prod";
    let secret_value = get_secret_value(&ssm_client, secret_name).await?;

    // create dynamodb client
    let dynamodb_client = aws_sdk_dynamodb::Client::new(&config);

    let state = AppState {
        jwt_secret: secret_value,
        db: dynamodb_client,
    };

    let app = Router::new().nest(
        "/auth",
        Router::new()
            .route("/health", get(health_check))
            .route("/register", post(register))
            .with_state(state),
    );

    run(app).await
}
