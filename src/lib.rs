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
//! The following algorithms are listed in the [Algorithm registry](https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-09.html#name-http-signature-algorithms-4):
//! * `hmac-sha256`
//! * `rsa-pss-sha512`
//! * `rsa-v1_5-sha256`
//! * `ecdsa-p256-sha256`

//!
//! ### Supported digest algorithms:
//! The following digest algorithmes are supported:
//!
//! * `SHA-256`
//! * `SHA-512`
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
