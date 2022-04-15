use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Malformed request for MockRequest
    #[error("Malformed request for MockRequest")]
    ParseError,
}
