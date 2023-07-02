//! Derived Components
//!
use std::cmp::PartialEq;
use std::fmt;
use std::str::FromStr;

use sfv::{BareItem, Item, Parameters, Parser, SerializeValue};

use crate::Error;

/// Section 2.2.1.
pub const AT_SIGNATURE_PARAMS: &str = "@signature-params";

/// Section 2.2.2.
pub const AT_METHOD: &str = "@method";

/// Section 2.2.3.
pub const AT_TARGET_URI: &str = "@target-uri";

/// Section 2.2.4
pub const AT_AUTHORITY: &str = "@authority";

/// Section 2.2.5
pub const AT_SCHEME: &str = "@scheme";

/// Section 2.2.6
pub const AT_REQUEST_TARGET: &str = "@request-target";

/// Section 2.2.7.
pub const AT_PATH: &str = "@path";

/// Section 2.2.8
pub const AT_QUERY: &str = "@query";

/// Section 2.2.9
pub const AT_QUERY_PARAMS: &str = "@query-params";

/// Section 2.2.10
pub const AT_STATUS: &str = "@status";

/// Section 2.2.11.
pub const AT_REQUEST_RESPONSE: &str = "@request-response";

/// Http-Signature Derived Components
///
/// In addition to HTTP fields, there are a number of different components
/// that can be derived from the control data, processing context, or other
/// aspects of the HTTP message being signed. Such derived components can be
/// included in the signature base by defining a component identifier and the
/// derivation method for its component value.
/// They are defined in the draft specification at
/// [Derived Components](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-17.html#name-derived-components)
#[derive(Debug, Clone)]
pub struct DerivedComponent {
    item: Item,
}

impl DerivedComponent {
    /// Create an instance
    pub fn new(name: &str) -> Self {
        let bi_name = BareItem::String(name.to_string());
        let sf_params = Parameters::new();
        let item = Item::with_params(bi_name, sf_params);
        Self { item }
    }

    /// In place, add a parameter to the inner SFV item
    pub fn with_param(mut self, key: &str, value: &str) -> Self {
        let bi_param_value = BareItem::String(value.into());
        self.item.params.insert(key.into(), bi_param_value);
        self
    }

    /// Get the name
    pub fn name(&self) -> &str {
        self.item.bare_item.as_str().unwrap()
    }

    /// Get the parameter
    pub fn param(&self, key: &str) -> Option<&str> {
        if let Some(x) = self.item.params.get(key) {
            x.as_str()
        } else {
            None
        }
    }

    /// Get the item
    pub fn item(&self) -> Item {
        self.item.to_owned()
    }
}

impl PartialEq for DerivedComponent {
    fn eq(&self, other: &Self) -> bool {
        self.item.eq(&other.item)
    }
}
impl Eq for DerivedComponent {}

use std::cmp::Ordering;

impl Ord for DerivedComponent {
    fn cmp(&self, other: &Self) -> Ordering {
        match &self.item.bare_item {
            BareItem::String(val) => {
                if let Some(s) = other.item.bare_item.as_str() {
                    return val.cmp(&s.into());
                }
                Ordering::Equal
            }
            BareItem::Token(val) => {
                if let Some(s) = other.item.bare_item.as_token() {
                    return val.cmp(&s.into());
                }
                Ordering::Equal
            }
            BareItem::Decimal(val) => {
                if let Some(s) = other.item.bare_item.as_decimal() {
                    return val.cmp(&s);
                }
                Ordering::Equal
            }
            BareItem::Integer(val) => {
                if let Some(s) = other.item.bare_item.as_int() {
                    return val.cmp(&s);
                }
                Ordering::Equal
            }
            BareItem::Boolean(val) => {
                if let Some(s) = other.item.bare_item.as_bool() {
                    return val.cmp(&s);
                }
                Ordering::Equal
            }
            BareItem::ByteSeq(val) => {
                if let Some(s) = other.item.bare_item.as_byte_seq() {
                    return val.cmp(s);
                }
                Ordering::Equal
            }
        }
    }
}

impl PartialOrd for DerivedComponent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl FromStr for DerivedComponent {
    type Err = Error;
    fn from_str(text: &str) -> Result<DerivedComponent, Self::Err> {
        if !text.starts_with("\"@") {
            // Bad input
            return Err(Error::DerivedComponentParse(text.to_string()));
        }
        let item = Parser::parse_item(text.as_bytes())
            .map_err(|x| Error::DerivedComponentParse(x.to_string()))?;
        Ok(Self { item })
    }
}

impl fmt::Display for DerivedComponent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = self.item.serialize_value().unwrap();
        write!(f, "{}", &val)
    }
}

impl From<Item> for DerivedComponent {
    fn from(item: Item) -> Self {
        Self { item }
    }
}

/// Derivable
pub trait Derivable<T> {
    /// Derivable
    fn derive_component(&self, component: &T) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    const QUERY_PARAMS: &str = r#""@query-params";name="param1""#;

    #[test]
    fn test_derived() {
        let derived = DerivedComponent::new(AT_PATH);
        assert_eq!(derived.to_string(), r#""@path""#);
    }

    #[test]
    fn test_serialize_derived_with_param() {
        let param = "param1";
        let dqp = DerivedComponent::new(AT_QUERY_PARAMS).with_param("name", param);

        assert_eq!(dqp.to_string(), QUERY_PARAMS);
    }

    #[test]
    fn test_parse_derived_with_param() {
        let dqp = DerivedComponent::from_str(QUERY_PARAMS).unwrap();

        let dqp2 = DerivedComponent::new(AT_QUERY_PARAMS).with_param("name", "param1");
        assert_eq!(dqp, dqp2);
    }

    #[test]
    fn test_parse_derived() {
        let dc = r#""@request-target""#;
        let dqp = DerivedComponent::from_str(dc).unwrap();
        dbg!(&dqp);
        let dqp2 = DerivedComponent::new(AT_REQUEST_TARGET);
        assert_eq!(dqp, dqp2);
    }
}
