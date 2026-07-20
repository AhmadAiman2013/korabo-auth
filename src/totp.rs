use crate::errors::AppError;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn verify_totp_code(secret: &str, code: &str) -> Result<bool, AppError> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
        None,
        "".to_string(),
    )
    .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    Ok(totp.check_current(code).unwrap_or(false))
}
