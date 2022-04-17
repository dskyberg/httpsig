use std::fmt;
use std::iter::Iterator;

use anyhow::Result;
use sfv::{BareItem, Dictionary, InnerList, Item, List, ListEntry, Parser, SerializeValue};

use crate::{Error, SignatureComponent, SignatureParams};

/// Wrapper for [sfv::InnerList]
pub struct ComponentList {
    /// Instance of [sfv::InnerList]
    pub inner: InnerList,
}

impl ComponentList {
    /// Create a new ComponentList from parts provided by CanonicalizeConofig
    pub fn new(components: Vec<SignatureComponent>, params: SignatureParams) -> Self {
        let items = components
            .iter()
            .map(|item| item.to_item())
            .collect::<Vec<Item>>();
        Self {
            inner: InnerList::with_params(items, params.params()),
        }
    }

    /// Convert the inner to an [sfv::List]
    pub fn as_list(&self) -> List {
        vec![ListEntry::InnerList(self.inner.clone())] as List
    }

    /// Get an item
    pub fn get_item(&self, key: &str) -> Option<Item> {
        for item in self.inner.items.iter() {
            if let Some(ikey) = item.bare_item.as_str() {
                if key.eq(ikey) {
                    return Some(item.to_owned());
                }
            }
        }
        None
    }
}

impl fmt::Display for ComponentList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = self
            .as_list()
            .serialize_value()
            .map_err(|_| std::fmt::Error)?;
        write!(f, "{}", &val)
    }
}

impl TryFrom<&ListEntry> for ComponentList {
    type Error = Error;
    fn try_from(li: &ListEntry) -> Result<Self, Self::Error> {
        if let ListEntry::InnerList(inner) = li {
            Ok(Self {
                inner: inner.clone(),
            })
        } else {
            Err(Error::SignatureInputError)
        }
    }
}

impl TryFrom<&List> for ComponentList {
    type Error = Error;
    fn try_from(list: &List) -> Result<Self, Self::Error> {
        if let Some(list_entry) = list.first() {
            Ok(Self::try_from(list_entry)?)
        } else {
            Err(Error::SignatureInputError)
        }
    }
}

/// Opaque struct storing a canonicalizeed signature base, and the
/// along with the signature components and metadata as a structured field.
pub struct SignatureInput {
    /// Signature Input label, such as `sig`
    pub label: String,
    /// Wrapper for [sfv::InnerList]
    pub list: ComponentList,
}

impl SignatureInput {
    /// Create an instance of SignatureInput
    pub fn new(
        label: String,
        components: Vec<SignatureComponent>,
        params: SignatureParams,
    ) -> Self {
        Self {
            label,
            list: ComponentList::new(components, params),
        }
    }

    /*
    /// Get an item from the inner list.
    pub fn get_item(&self, key: &str) -> Option<SignatureComponent> {
       Some(SignatureComponent::from(self.list.get_item(key)?))
    }
    */
    /// Get a parameter from the list
    pub fn get_param(&self, key: &str) -> Option<&BareItem> {
        self.list.inner.params.get(key)
    }
}

impl fmt::Display for SignatureInput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dict = Dictionary::new();

        dict.insert(
            self.label.to_owned(),
            ListEntry::InnerList(self.list.inner.clone()),
        );
        let val = dict.serialize_value().map_err(|_| std::fmt::Error)?;
        write!(f, "{}", &val)
    }
}

/// Parse the Signature-Input header into a ComponentList instance
///
/// The Signature-input header is formatted as:
/// ```text
/// <label> =("header1" "@derived" "@derived-sf";key="value"...);alg="<signing alg>";[created=<ts>;][exxpires=<ts>;]keyid="<key>";[nonce=<nonce>]
/// ```
/// Example:
/// ```text
/// sig=("@method" "@scheme" "@authority" "@target-uri" "@request-target");alg="hmac-sha256";created=1640871972;keyid="My Key";nonce="some_random_nonce"
/// ```
impl TryFrom<&str> for SignatureInput {
    type Error = Error;
    fn try_from(signature_input_header: &str) -> Result<Self, Self::Error> {
        let dict = Parser::parse_dictionary(signature_input_header.as_bytes()).map_err(|s| {
            info!("Verification Failed: failed to parse SignatureInput");
            Error::SignatureInputParseError(s.to_string())
        })?;

        if let Some((label, list_entry)) = dict.first() {
            // We have a label and an inner list.
            // Pull the component items from the
            Ok(Self {
                label: label.clone(),
                list: ComponentList::try_from(list_entry)?,
            })
        } else {
            info!("Verification Failed: malformed structured field");
            Err(Error::SignatureInputError)
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_serialize() {}
}
