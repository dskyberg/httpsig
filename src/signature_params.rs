/// TODO:  Establish the SignatureParameters capability to manage the supported parameters:
/// * created
/// * expires
/// * nonce
/// * alg
/// * keyid
///
/// We will use the [sfv::Parameters] as the base type and extend around that
///
use std::default::Default;

use crate::sfv::{BareItem, Parameters};

/// `created` parameter name
pub(crate) const CREATED: &str = "created";
/// `expires` parameter name
pub(crate) const EXPIRES: &str = "expires";
/// `nonce` parameter name
pub(crate) const NONCE: &str = "nonce";
/// `alg` parameter name
pub(crate) const ALG: &str = "alg";
/// `keyid` parameter name
pub(crate) const KEYID: &str = "keyid";

/// Wrapper for [sfv::Parameters]
#[derive(Clone, Debug, Default)]
pub(crate) struct SignatureParams {
    params: Parameters,
}

impl From<&Parameters> for SignatureParams {
    fn from(params: &Parameters) -> Self {
        Self {
            params: params.clone(),
        }
    }
}

impl SignatureParams {
    /*
    /// Create an instance
    pub fn new() -> Self {
        Self::default()
    }
    */

    /// Get the params
    pub fn params(&self) -> Parameters {
        self.params.clone()
    }

    /// Set the `created` param in place
    pub fn set_created(&mut self, created: i64) -> &mut Self {
        self.params
            .insert(String::from(CREATED), BareItem::Integer(created));
        self
    }

    /*
    /// Chainable, set the `created`
    pub fn with_created(mut self, created: i64) -> Self {
        self.set_created(created);
        self
    }
    */

    /// Get the `created` param
    pub fn get_created(&self) -> Option<i64> {
        self.params.get(CREATED).and_then(|x| x.as_int())
    }

    /// Set the `expires` param in place
    pub fn set_expires(&mut self, expires: i64) -> &mut Self {
        self.params
            .insert(String::from(EXPIRES), BareItem::Integer(expires));
        self
    }

    /*
    /// Chainable set the `expires` param
    pub fn with_expires(mut self, expires: i64) -> Self {
        self.set_expires(expires);
        self
    }
    */

    /// Get the `expires` param
    pub fn get_expires(&self) -> Option<i64> {
        self.params.get(EXPIRES).and_then(|x| x.as_int())
    }

    /// Set the `nonce` param in place
    pub fn set_nonce(&mut self, nonce: &str) -> &mut Self {
        self.params
            .insert(String::from(NONCE), BareItem::Token(nonce.to_string()));
        self
    }

    /*
    /// Chainable set the `nonce` param
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.set_nonce(nonce);
        self
    }
    */

    /*
    /// Get the `nonce` param
    pub fn get_nonce(&self) -> Option<&str> {
        self.params.get(NONCE).and_then(|x| x.as_str())
    }
    */

    /// Set the `alg` param in place
    pub fn set_alg(&mut self, alg: &str) -> &mut Self {
        self.params
            .insert(String::from(ALG), BareItem::String(alg.to_string()));
        self
    }

    /*
    /// Chainable set the `alg` param
    pub fn with_alg(mut self, alg: &str) -> Self {
        self.set_alg(alg);
        self
    }
    */

    /// Get the `alg` param
    pub fn get_alg(&self) -> Option<&str> {
        self.params.get(ALG).and_then(|x| x.as_str())
    }

    /// Set the `keyid` param in place
    pub fn set_keyid(&mut self, keyid: &str) -> &mut Self {
        self.params
            .insert(String::from(KEYID), BareItem::String(keyid.to_string()));
        self
    }

    /*
    /// Chainable set the `keyid` param
    pub fn with_keyid(mut self, keyid: &str) -> Self {
        self.set_keyid(keyid);
        self
    }
    */

    /// Get the `keyid` param
    pub fn get_keyid(&self) -> Option<&str> {
        self.params.get(KEYID).and_then(|x| x.as_str())
    }

    /*
    /// Set a parameter other than one of the named params
    pub fn set_item(&mut self, key: &str, item: BareItem) -> &mut Self {
        self.params.insert(String::from(key), item);
        self
    }

    /// Chainable, set a parameter other than one of the named params
    pub fn with_item(mut self, key: &str, item: BareItem) -> Self {
        self.set_item(key, item);
        self
    }

    /// Get a parameter as an [sfv::BareItem]
    pub fn get_item(&self, key: &str) -> Option<&BareItem> {
        self.params.get(key)
    }
    */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let params = SignatureParams::new().with_nonce("nonce");
        dbg!(params);
    }
}
