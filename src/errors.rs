use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::query::QueryError;
use aws_sdk_sqs::error::SdkError as SQSSdkError;
use aws_sdk_sqs::operation::send_message::SendMessageError;
use aws_sdk_ssm::error::SdkError;
use aws_sdk_ssm::operation::get_parameter::GetParameterError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use lambda_http::tracing::log::warn;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SqsError {
    #[error("Send message error: {0}")]
    SendMessageError(#[from] SQSSdkError<SendMessageError>),
}

#[derive(Debug, Error)]
pub enum DynamodbError {
    #[error("Query error: {0}")]
    QueryError(#[from] SdkError<QueryError>),

    #[error("Get Item error: {0}")]
    GetItemError(#[from] SdkError<GetItemError>),

    #[error("Put Item error: {0}")]
    PutItemError(#[from] SdkError<PutItemError>),
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("SSM error: {0}")]
    GetParameterError(#[from] SdkError<GetParameterError>),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Dynamodb error: {0}")]
    DBError(#[from] DynamodbError),

    #[error("Password hashing error: {0}")]
    PasswordHashingError(#[from] argon2::password_hash::Error),

    #[error("SQS error: {0}")]
    SqsError(#[from] SqsError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::GetParameterError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::JwtError(_) => StatusCode::UNAUTHORIZED,
            AppError::DBError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::PasswordHashingError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SqsError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SerializationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let message = match &self {
            AppError::NotFound(msg) => msg.clone(),
            AppError::InternalServerError(msg) => {
                warn!("Internal server error: {}", msg);
                "An unexpected error occurred".to_string()
            }
            AppError::GetParameterError(e) => {
                warn!("SSM error: {:?}", e);
                "An unexpected error occurred".to_string()
            }
            AppError::JwtError(e) => {
                warn!("JWT error: {:?}", e);
                "Invalid token".to_string()
            }
            AppError::DBError(e) => {
                warn!("DynamoDB error: {:?}", e);
                "An unexpected error occurred".to_string()
            }
            AppError::PasswordHashingError(e) => {
                warn!("Password hashing error: {:?}", e);
                "An unexpected error occurred".to_string()
            }

            AppError::SqsError(e) => {
                warn!("SQS error: {:?}", e);
                "An unexpected error occurred".to_string()
            }

            AppError::SerializationError(e) => {
                warn!("Serialization error: {:?}", e);
                "An unexpected error occurred".to_string()
            }

            _ => self.to_string(),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
