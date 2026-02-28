use crate::errors::{AppError, SqsError};
use crate::model::UserRegisteredEvent;
use aws_sdk_sqs::Client;

pub async fn publish_user_registered(
    client: &Client,
    queue_url: &str,
    event: &UserRegisteredEvent,
) -> Result<(), AppError> {
    let body = serde_json::to_string(event)?;

    client
        .send_message()
        .queue_url(queue_url)
        .message_body(body)
        .send()
        .await
        .map_err(SqsError::SendMessageError)?;

    Ok(())
}
