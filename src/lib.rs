#![deny(missing_docs)]
//! Implementation of the IETF draft [HTTP Message Signatures](https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-09.html)
//!
//! ## Features
//!
//! This crate is intended to be used with multiple different HTTP clients and/or servers.
//! As such, client/server-specific implementations are gated by correspondingly named
//! features.
//!
//! ### Supported crates:
//!
//! | Crate / Feature name                              | Client/Server | Notes                                                         |
//! | ------------------------------------------------- | ------------- | ------------------------------------------------------------- |
//! | [reqwest](https://docs.rs/reqwest/latest/reqwest)       | Client        | Supports blocking and non-blocking requests.<sup>1</sup>      |
//! | [actix-web](https://docs.rs/actix-web/latest/actix_web)       | Server        |                                                               |
//!
//! 1. Due to limitations of the reqwest API, digests can only be calculated automatically for non-blocking non-streaming requests. For
//!    blocking or streaming requests, the user must add the digest manually before signing the request, or else the `Digest` header will
//!    not be included in the signature.
//!
//! ### Supported signature algorithms:
//!
//! Signature Altorithms: `https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-09.html#name-signature-algorithm-methods`
//! - `hmac-sha256`
//!
//! ### Supported digest algorithms:
//!
//! ## Example usage (reqwest)
//!
//! ```rust,ignore
//! use http_sig::*;
//!
//! const SECRET_KEY: &[u8] = b"secret";
//! let label = "sig";
//! let key_id = "My Key";
//! let config = SigningConfig::new_default(&label, &key_id, SECRET_KEY);
//!
//! let client = reqwest::blocking::Client::new();
//!
//! let req = client
//!     .get("http://localhost:8080/")
//!     .build()
//!     .unwrap()
//!     .signed(&config)
//!     .unwrap();
//!
//! let result = client.execute(req).unwrap();
//! ```
//! [SEMANTICS]:  https://tools.ietf.org/id/draft-ietf-httpbis-semantics-17.html

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
pub(crate) use signature_params::*;

mod signature_input;
pub(crate) use signature_input::*;

mod derived;
pub use derived::*;

mod canonicalize;
pub(crate) use canonicalize::*;

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
