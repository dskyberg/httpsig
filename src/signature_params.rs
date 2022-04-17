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

use sfv::{BareItem, Parameters};

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
pub struct SignatureParams {
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

    /// Get the 'nonce' param
    #[allow(dead_code)]
    pub fn get_nonce(&self) -> Option<&str> {
        self.params.get(NONCE).and_then(|x| x.as_token())
    }

    /// Set the `alg` param in place
    pub fn set_alg(&mut self, alg: &str) -> &mut Self {
        self.params
            .insert(String::from(ALG), BareItem::String(alg.to_string()));
        self
    }

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

    /// Get the `keyid` param
    pub fn get_keyid(&self) -> Option<&str> {
        self.params.get(KEYID).and_then(|x| x.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let params = Parameters::new();
        let mut signature_params = SignatureParams::from(&params);
        signature_params.set_nonce("nonce");
        signature_params.set_alg("alg");
        dbg!(&signature_params);
        assert_eq!(signature_params.get_nonce(), Some("nonce"));
        assert_eq!(signature_params.get_alg(), Some("alg"));
    }
}
