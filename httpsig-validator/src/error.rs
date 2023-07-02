use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed request for MockRequest
    #[error("Malformed request for MockRequest")]
    ParseError,
    #[error("Bad Arguement: {0}")]
    BadArg(String),
}
