use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use http::header::HeaderName;
use sfv::{BareItem, Item};

use crate::{DerivedComponent, Error};

/// A component name which can be incorporated into a HTTP signature.
///
/// Names can refer to a standard HTTP header, or a [DerivedComponent]
/// used for including additional information into a signature.
/// A DerivedCompnent may be a [structured field](https://www.rfc-editor.org/rfc/rfc8941)
/// with parameters, such as for [@query-params](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-17.html#name-query-parameters)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureComponent {
    /// This header is one of the special "pseudo-headers"
    Derived(DerivedComponent),
    /// This header is a normal HTTP heaeder.
    Header(HeaderName),
}

impl SignatureComponent {
    /// Returns the string representation of the header, as it will appear
    /// in the HTTP signature.
    pub fn to_item(&self) -> Item {
        match self {
            Self::Derived(dc) => dc.item(),
            Self::Header(h) => Item::new(BareItem::String(h.as_str().to_owned())),
        }
    }

    /// Return a Header type component as a HeaderName
    pub fn to_header_name(&self) -> Option<HeaderName> {
        match self {
            Self::Header(h) => Some(h.to_owned()),
            _ => None,
        }
    }
}

impl fmt::Display for SignatureComponent {
    /// Returns the string representation of the header, as it will appear
    /// in the HTTP signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Derived(h) => f.write_str(h.to_string().as_ref()),
            Self::Header(h) => f.write_str(h.as_str()),
        }
    }
}

impl FromStr for SignatureComponent {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('@') || s.starts_with('"') {
            DerivedComponent::from_str(s).map(Into::into)
        } else {
            HeaderName::from_str(s)
                .map_err(|_| Error::HeaderNameParse(s.to_owned()))
                .map(Into::into)
        }
    }
}

impl Ord for SignatureComponent {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for SignatureComponent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<HeaderName> for SignatureComponent {
    fn from(name: HeaderName) -> Self {
        Self::Header(name)
    }
}

impl From<DerivedComponent> for SignatureComponent {
    fn from(dc: DerivedComponent) -> Self {
        Self::Derived(dc)
    }
}

impl From<Item> for SignatureComponent {
    fn from(item: Item) -> Self {
        let name = item.bare_item.as_str().unwrap();
        if name.starts_with('@') {
            Self::Derived(item.into())
        } else {
            Self::Header(HeaderName::from_str(name).unwrap())
        }
    }
}
#[allow(clippy::from_over_into)]
impl Into<Item> for SignatureComponent {
    fn into(self) -> Item {
        match self {
            SignatureComponent::Derived(derived) => derived.item(),
            SignatureComponent::Header(name) => Item::new(BareItem::String(name.to_string())),
        }
    }
}

/// Proposed [Content-Digest](https://httpwg.org/http-extensions/draft-ietf-httpbis-digest-headers.html#name-the-content-digest-field) header
pub const CONTENT_DIGEST: &str = "content-digest";
/// Standard Digest header .
pub const DIGEST: &str = "digest";
/// Standard Signature header.
pub const SIGNATURE: &str = "signature";
/// Standard Signature-input header.
pub const SIGNATURE_INPUT: &str = "signature-input";

/// Proposed [Content-Digest](https://httpwg.org/http-extensions/draft-ietf-httpbis-digest-headers.html#name-the-content-digest-field) header
pub fn content_digest_header() -> HeaderName {
    HeaderName::from_static(CONTENT_DIGEST)
}

/// Standard Digest header
pub fn digest_header() -> HeaderName {
    HeaderName::from_static(DIGEST)
}

/// Standard Signature header
pub fn signature_header() -> HeaderName {
    HeaderName::from_static(SIGNATURE)
}

/// Standard Signature-Input header
pub fn signature_input_header() -> HeaderName {
    HeaderName::from_static(SIGNATURE_INPUT)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        let x = SignatureComponent::from_str(r#""@request-taget""#);
        dbg!(&x);
    }
}
