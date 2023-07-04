//! Canonicalize request headers and derived components
//!
//! The http-signatures spec provides guidance for ensuring all signature
//! components, including standard headers, are placed in a canonical
//! format for proper digesting.  For instance, request crates tht allow
//! multiple instances of a single header need to be canonicalized into a
//! single header with multiple values.
//!
//! Any object that derives the RequestLike trait must also provide values
//! for Derived Components.  Derived Component are not headers, but are often
//! derived from request header and URI values.

use itertools::{Either, Itertools};
use std::iter::Iterator;

use crate::{DerivedComponent, Error, Result, SignatureComponent, SignatureInput, SignatureParams};

/// Base trait for all request types
pub trait RequestLike {
    /// Returns an existing component value on the request. Either from a standard
    /// header or from a derived component. This method *must* reflect changes made
    /// by the `ClientRequestLike::set_header` method.
    fn derive(&self, header: &SignatureComponent) -> Option<String>;

    /// Returns true if this request contains a value for the specified SignatureComponent. If this
    /// returns true, following requests to `derive()` for the same name must return a
    /// value.
    fn has_component(&self, component: &SignatureComponent) -> bool;
}

impl<T: RequestLike> RequestLike for &T {
    fn derive(&self, component: &SignatureComponent) -> Option<String> {
        (**self).derive(component)
    }
    fn has_component(&self, component: &SignatureComponent) -> bool {
        (**self).has_component(component)
    }
}

/// Configuration for computing the canonical [Signature Base](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-17.html#name-creating-the-signature-base) of a request.
///
/// The signature string is composed of the set of the components configured on the
/// [crate::SigningConfig] along with the set of signing context components. This set
/// of components is repeated in the `@signature-params`  derived componnent, that
/// is automatically included in the Signature Base
/// as well as the final `Signature-input` header that is placed on the request.
#[derive(Debug, Default)]
pub struct CanonicalizeConfig {
    label: Option<String>,
    components: Vec<SignatureComponent>,
    params: SignatureParams,
}

impl CanonicalizeConfig {
    /// Creates a new canonicalization configuration using the default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create th config from the Signature-Input header of a request
    pub fn from_signature_input(input: &str) -> Result<Self> {
        let signature_input = SignatureInput::try_from(input)?;
        Ok(Self::from(&signature_input))
    }

    /// Create a new SignatureInput instancee from CanonicalizeConfig parts
    pub fn to_signature_input(&self) -> SignatureInput {
        SignatureInput::new(
            self.get_label(),
            self.components.clone(),
            self.params.clone(),
        )
    }

    /// If a label was set, return it.  Or return the default "sig".
    pub fn get_label(&self) -> String {
        match &self.label {
            Some(val) => val.to_owned(),
            None => "sig".to_owned(),
        }
    }

    /// Set the label in place
    pub fn set_label(&mut self, label: &str) -> &mut Self {
        self.label = Some(String::from(label));
        self
    }

    /// Set the components to include in the signature
    pub fn with_components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.components = components;
        self
    }

    /// Set the components to include in the signature
    pub fn set_components(&mut self, components: Vec<SignatureComponent>) -> &mut Self {
        self.components = components;
        self
    }

    /*
    /// Set the SignatureParams
    pub fn set_params(&mut self, params: SignatureParams) -> &mut Self {
        self.params = params;
        self
    }
    */

    /// Get the `created` context
    pub fn created(&self) -> Option<i64> {
        self.params.get_created()
    }

    /// Add `created` to the context
    pub fn set_created(&mut self, ts: i64) {
        self.params.set_created(ts);
    }

    /// Get the `expires` context
    pub fn expires(&self) -> Option<i64> {
        self.params.get_expires()
    }

    /// Add `expires` to the context
    pub fn set_expires(&mut self, ts: i64) {
        self.params.set_expires(ts);
    }

    /// Get the `alg` context
    pub fn alg(&self) -> Option<&str> {
        self.params.get_alg()
    }

    /// Add `alg` to the context
    pub fn set_alg(&mut self, alg: &str) {
        self.params.set_alg(alg);
    }

    /// Add `nonce` to the context
    pub fn set_nonce(&mut self, nonce: &str) {
        self.params.set_nonce(nonce);
    }

    /// Get the `keyid` context
    pub fn keyid(&self) -> Option<&str> {
        self.params.get_keyid()
    }

    /// Add `keyid` to the context
    pub fn set_keyid(&mut self, key_id: &str) {
        self.params.set_keyid(key_id);
    }
}

impl From<&SignatureInput> for CanonicalizeConfig {
    /// Decompose the InnerList withint a SignatureComponent
    fn from(input: &SignatureInput) -> Self {
        let components = input
            .list
            .inner
            .items
            .iter()
            .map(|item| SignatureComponent::from(item.to_owned()))
            .collect::<Vec<SignatureComponent>>();

        let params = SignatureParams::from(&input.list.inner.params);

        Self {
            label: Some(input.label.to_owned()),
            components,
            params,
        }
    }
}

/// Extension method for computing the canonical "signature string" of a request.
pub trait CanonicalizeExt {
    /// Compute the canonical representation of this request
    fn canonicalize(&self, config: &CanonicalizeConfig) -> Result<(Vec<u8>, SignatureInput)>;
}

impl<T: RequestLike> CanonicalizeExt for T {
    /// Canonicalize the message
    ///
    /// The purpose of `canonicalize` is to fulfill steps 4 and 5 of section 3.1 Creating a Signature.
    /// There are 3 steps to this process:
    /// 1. Construct the `@signature-params` as a serialized [sfv::Item] using the list components
    ///    and metadata parameters
    /// 2. Construct the SignatureInput field as an [sfv::Dictionary] using
    ///    the config label as the field key and the `@signature-params value as the field value.
    /// 3. Construct the Signature Base, including the `@signature-params`
    fn canonicalize(&self, config: &CanonicalizeConfig) -> Result<(Vec<u8>, SignatureInput)> {
        // Derive the value of each component.  If any component is missing, error out
        let (mut components, missing_components): (Vec<_>, Vec<_>) = config
            .components
            .iter()
            .cloned()
            .partition_map(|component| {
                if let Some(value) = self.derive(&component) {
                    Either::Left((component, value))
                } else {
                    Either::Right(component)
                }
            });

        // All available components have been derived.  If any requested components
        // were not available, then we cannot proceed.
        if !missing_components.is_empty() {
            log::trace!(
                "CanonicalizeConfig is missing required components: {:?}",
                &missing_components
            );
            return Err(Error::MissingComponents(missing_components));
        }

        // Add the @signature-param DerivedComponent, built on the components
        // and the signature context parameters

        let signature_input: SignatureInput = config.to_signature_input();

        // Add the `@signature_params` derived component to the signature base set
        components.push((
            SignatureComponent::Derived(DerivedComponent::new(crate::AT_SIGNATURE_PARAMS)),
            signature_input.list.to_string(),
        ));

        let signature_base = components
            .iter()
            .map(|(name, value)| match name {
                SignatureComponent::Header(_) => format!(r#""{}": {}"#, &name, &value),
                SignatureComponent::Derived(_) => format!("{}: {}", &name, &value),
            })
            .collect::<Vec<String>>()
            .join("\n")
            .as_bytes()
            .to_vec();
        log::trace!("Signature Base [u8]: {:?}", &signature_base);
        log::trace!(
            "Signature Base String: {}",
            &String::from_utf8(signature_base.clone()).expect("failed to convert to string")
        );
        log::trace!("SignatureInut: {:?}", &signature_input);
        Ok((signature_base, signature_input))
    }
}

#[cfg(test)]
mod tests {
    use crate::CanonicalizeConfig;

    #[test]
    fn test_from_sig_input() {
        let sig_input =
            r#"sig=("host" "date" "digest");alg="rsa-v1_5-sha256";keyid="test-key-rsa""#;
        let config = CanonicalizeConfig::from_signature_input(sig_input).unwrap();
        let signature_input = config.to_signature_input();
        assert_eq!(format!("{}", &signature_input), sig_input);
    }
}
