use crate::SignatureComponent;
use http::header::InvalidHeaderValue;
use thiserror::Error;

/// Shorthand for standard result
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The types of error which may occur whilst computing the canonical "signature string"
/// for a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Malformed request for MockRequest
    #[error("Malformed request for MockRequest")]
    ParseError,
    /// One or more components required to be part of the signature was not present
    /// on the request, and the `skip_missing` configuration option
    /// was disabled.
    #[error("Missing components required for signature: {0:?}")]
    MissingComponents(Vec<SignatureComponent>),

    /// SignatureInput parsing error
    #[error("Failed to parse SignatureInput: {0:?}")]
    SignatureInputParseError(String),

    /// Malformed `signature-input component
    #[error("Malformed Signature-Input component")]
    SignatureInputError,

    /// A header required to be part of the signature was not present
    /// on the request, and the `skip_missing` configuration option
    /// was disabled.
    #[error("Failed to canonicalize request")]
    Canonicalize,

    /// The signature creation date was in the future
    #[error("Signature creation date was in the future")]
    InvalidSignatureCreationDate,

    /// The signature expires date was in the past
    #[error("Signature expires date was in the past")]
    InvalidSignatureExpiresDate,

    /// Unrecognized derived component
    #[error("Unrecognized derived component: {0:?}")]
    UnrecognizedDerivedComponent(String),

    /// Failed to parse DerivedComponent
    #[error("Failed to parse DerivedComponent: {0:?}")]
    DerivedComponentParse(String),

    /// Failed to parse Headername
    #[error("Failed to parse HeaderName: {0:?}")]
    HeaderNameParse(String),
    /// Failed to serialize
    #[error("Failed to serialize")]
    FailedToSerialize,

    /// Failed to convert signature string to header value
    #[error("Failed to create signature header value")]
    ConvertHeader(#[from] InvalidHeaderValue),
}
