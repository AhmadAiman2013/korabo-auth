use crate::errors::{AppError};

pub async fn get_secret_value(ssm_client: &aws_sdk_ssm::Client, secret_name: &str) -> Result<String, AppError> {
    let resp = ssm_client
        .get_parameter()
        .name(secret_name)
        .with_decryption(true)
        .send()
        .await?;

    if let Some(parameter) = resp.parameter {
        if let Some(value) = parameter.value {
            Ok(value)
        } else {
            Err(AppError::NotFound(format!("Value not found for parameter: {}", secret_name)))
        }
    } else {
        Err(AppError::NotFound(format!("Parameter not found: {}", secret_name)))
    }
}