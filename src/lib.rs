#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use sha2::Sha256;

pub use http;
pub use sfv;
pub use url;

const DATE_FORMAT: &str = "%a, %d %b %Y %T GMT";
type DefaultSignatureAlgorithm = algorithm::HmacSha256;
type DefaultDigestAlgorithm = Sha256;

#[macro_use]
mod macros;

mod errors;
pub use errors::*;

mod algorithm;
pub use algorithm::*;

mod signature_component;
pub use signature_component::*;

mod signature_params;
pub use signature_params::*;

mod signature_input;
pub use signature_input::*;

mod derived;
pub use derived::*;

mod canonicalize;
pub use canonicalize::*;

mod signing;
pub use signing::*;

mod verifying;
pub use verifying::*;

/// Module containg a mock request type which implements both
/// `ClientRequestLike` and `ServerRequestLike` for testing.
//pub mod mock_request;

#[cfg(feature = "reqwest")]
mod reqwest_impls;
#[cfg(feature = "reqwest")]
pub use reqwest_impls::*;

#[cfg(feature = "actix")]
mod actix_web_impls;
#[cfg(feature = "actix")]
pub use actix_web_impls::*;
