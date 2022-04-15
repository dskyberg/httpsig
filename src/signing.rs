use chrono::Utc;
use http::header::{HeaderName, HeaderValue, DATE, HOST};
use log::trace;
use sha2::Digest;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{
    digest_header, signature_header, signature_input_header, CanonicalizeConfig, CanonicalizeExt,
    DefaultDigestAlgorithm, DefaultSignatureAlgorithm, Error, HttpDigest, HttpSignatureSign,
    RequestLike, SignatureComponent, DATE_FORMAT,
};

/// This trait is to be implemented for types representing an outgoing
/// HTTP request. The HTTP signing extension methods are available on
/// any type implementing this trait.
pub trait ClientRequestLike: RequestLike {
    /// Returns the host for the request (eg. "example.com") in case the Host header has
    /// not been set explicitly.
    /// When implementing this trait, do not just read the `Host` header from the request -
    /// this method will only be called when the `Host` header is not set.
    fn host(&self) -> Option<String> {
        None
    }
    /// Add a header to the request. This function may be used to set the `Date` and `Digest`
    /// components if not already present depending on the configuration. The `Authorization`
    /// header will always be set assuming the message was signed successfully.
    fn set_header(&mut self, header: HeaderName, value: HeaderValue);
    /// Compute the digest using the provided HTTP digest algorithm. If this is not possible,
    /// then return `None`. This may require buffering the request data into memory.
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String>;
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum SignatureCreated {
    Omit,
    Automatic,
    Absolute(i64),
}

impl SignatureCreated {
    fn get(self, ts: i64) -> Option<i64> {
        match self {
            Self::Omit => None,
            Self::Automatic => Some(ts),
            Self::Absolute(ts) => Some(ts),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum SignatureExpires {
    Omit,
    Relative(i64),
    Absolute(i64),
}

impl SignatureExpires {
    fn get(self, ts: i64) -> Option<i64> {
        match self {
            Self::Omit => None,
            Self::Relative(offset) => Some(ts.saturating_add(offset)),
            Self::Absolute(ts) => Some(ts),
        }
    }
}

/// The configuration used for signing HTTP requests.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    label: String,
    signature: Arc<dyn HttpSignatureSign>,
    digest: Arc<dyn HttpDigest>,
    key_id: String,
    nonce: Option<String>,
    components: Vec<SignatureComponent>,
    compute_digest: bool,
    add_date: bool,
    add_host: bool,
    skip_missing: bool,
    signature_created: SignatureCreated,
    signature_expires: SignatureExpires,
}

impl SigningConfig {
    /// Creates a new signing configuration using the default signature algorithm, and the
    /// specified key ID and key.
    pub fn new_default(label: &str, key_id: &str, key: &[u8]) -> Self {
        Self::new(label, key_id, DefaultSignatureAlgorithm::new(key))
    }

    /// Creates a new signing configuration using a custom signature algorithm, and the specified
    /// key ID.
    pub fn new<SigAlg: HttpSignatureSign>(label: &str, key_id: &str, signature: SigAlg) -> Self {
        SigningConfig {
            label: label.into(),
            signature: Arc::new(signature),
            digest: Arc::new(DefaultDigestAlgorithm::new()),
            key_id: key_id.into(),
            nonce: None,
            components: Vec::new(),
            compute_digest: true,
            add_date: true,
            add_host: true,
            skip_missing: true,
            signature_created: SignatureCreated::Omit,
            signature_expires: SignatureExpires::Omit,
        }
    }

    /// Returns the key ID.
    pub fn key_id(&self) -> &str {
        self.key_id.as_ref()
    }
    /// Returns the nonce.
    pub fn nonce(&self) -> Option<String> {
        self.nonce.as_ref().cloned()
    }
    /// Sets the nonce (in-place).
    pub fn set_nonce(&mut self, nonce: &str) -> &mut Self {
        self.nonce = Some(nonce.into());
        self
    }
    /// Sets the nonce.
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.set_nonce(nonce);
        self
    }

    /// Returns the HTTP digest algorithm.
    pub fn digest(&self) -> &dyn HttpDigest {
        &*self.digest
    }
    /// Sets the HTTP digest algorithm (in-place).
    fn set_digest<DigestAlg: HttpDigest>(&mut self, digest: DigestAlg) -> &mut Self {
        self.digest = Arc::new(digest);
        self
    }
    /// Sets the HTTP digest algorithm.
    pub fn with_digest<DigestAlg: HttpDigest>(mut self, digest: DigestAlg) -> Self {
        self.set_digest(digest);
        self
    }
    /// Returns whether the digest will be automatically computed
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn compute_digest(&self) -> bool {
        self.compute_digest
    }
    /// Controls whether the digest will be automatically computed
    /// when not already present (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_compute_digest(&mut self, compute_digest: bool) -> &mut Self {
        self.compute_digest = compute_digest;
        self
    }
    /// Controls whether the digest will be automatically computed
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn with_compute_digest(mut self, compute_digest: bool) -> Self {
        self.set_compute_digest(compute_digest);
        self
    }
    /// Returns whether the current date and time will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn add_date(&self) -> bool {
        self.add_date
    }
    /// Controls whether the current date and time will be added to the request
    /// when not already present (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_add_date(&mut self, add_date: bool) -> &mut Self {
        self.add_date = add_date;
        self
    }
    /// Controls whether the current date and time will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn with_add_date(mut self, add_date: bool) -> Self {
        self.set_add_date(add_date);
        self
    }
    /// Returns whether the host will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn add_host(&self) -> bool {
        self.add_host
    }
    /// Controls whether the host will be added to the request
    /// when not already present (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_add_host(&mut self, add_host: bool) -> &mut Self {
        self.add_host = add_host;
        self
    }
    /// Controls whether the host will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn with_add_host(mut self, add_host: bool) -> Self {
        self.set_add_host(add_host);
        self
    }
    /// Returns the list of components to include in the signature. components in this list
    /// which are not present in the request itself will be skipped when signing the request.
    ///
    /// This list contains `(request-target)`, `host`, `date` and `digest` by default.
    pub fn components(&self) -> impl IntoIterator<Item = &SignatureComponent> {
        &self.components
    }
    /// Controls the list of components to include in the signature (in-place). Headers in this list
    /// which are not present in the request itself will be skipped when signing the request.
    ///
    /// This list contains `host`, `date` and `digest` by default.
    pub fn set_components(&mut self, components: &[SignatureComponent]) -> &mut Self {
        self.components = components.to_vec();
        self
    }
    /// Controls the list of components to include in the signature. Headers in this list
    /// which are not present in the request itself will be skipped when signing the request.
    pub fn with_components(mut self, components: &[SignatureComponent]) -> Self {
        self.set_components(components);
        self
    }
    /// Returns whether the missing components will be skipped
    /// when not present, or if signing will fail instead.
    ///
    /// This is set to `true` by default.
    pub fn skip_missing(&self) -> bool {
        self.skip_missing
    }
    /// Controls whether the missing components will be skipped
    /// when not present, or if signing will fail instead.
    ///
    /// This is set to `true` by default.
    pub fn set_skip_missing(&mut self, skip_missing: bool) -> &mut Self {
        self.skip_missing = skip_missing;
        self
    }
    /// Controls whether the missing components will be skipped
    /// when not present, or if signing will fail instead.
    ///
    /// This is set to `true` by default.
    pub fn with_skip_missing(mut self, skip_missing: bool) -> Self {
        self.set_skip_missing(skip_missing);
        self
    }
    /// Ensures a signature created date will be added
    /// automatically with the current time.
    ///
    /// This is off by default.
    pub fn set_signature_created_auto(&mut self) -> &mut Self {
        self.signature_created = SignatureCreated::Automatic;
        self
    }
    /// Ensures a signature created date will be added
    /// automatically with the current time.
    ///
    /// This is off by default.
    pub fn with_signature_created_auto(mut self) -> Self {
        self.signature_created = SignatureCreated::Automatic;
        self
    }
    /// Determines if a signature created date will be added
    /// automatically with the current time.
    ///
    /// This is off by default.
    pub fn signature_created_auto(&self) -> bool {
        self.signature_created == SignatureCreated::Automatic
    }
    /// Ensures a signature created date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn set_signature_created_at(&mut self, ts: i64) -> &mut Self {
        self.signature_created = SignatureCreated::Absolute(ts);
        self
    }
    /// Ensures a signature created date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn with_signature_created_at(mut self, ts: i64) -> Self {
        self.signature_created = SignatureCreated::Absolute(ts);
        self
    }
    /// Determines if a signature created date will be added
    /// with a specific unix timestamp.
    ///
    /// This is off by default.
    pub fn signature_created_at(&self) -> Option<i64> {
        if let SignatureCreated::Absolute(ts) = self.signature_created {
            Some(ts)
        } else {
            None
        }
    }
    /// Ensures a signature expires date will be added
    /// automatically relative to the current time.
    ///
    /// This is off by default.
    pub fn set_signature_expires_relative(&mut self, offset: i64) -> &mut Self {
        self.signature_expires = SignatureExpires::Relative(offset);
        self
    }
    /// Ensures a signature expires date will be added
    /// automatically relative to the current time.
    ///
    /// This is off by default.
    pub fn with_signature_expires_auto(mut self, offset: i64) -> Self {
        self.signature_expires = SignatureExpires::Relative(offset);
        self
    }
    /// Determines if a signature expires date will be added
    /// automatically relative to the current time.
    ///
    /// This is off by default.
    pub fn signature_expires_relative(&self) -> Option<i64> {
        if let SignatureExpires::Relative(offset) = self.signature_expires {
            Some(offset)
        } else {
            None
        }
    }
    /// Ensures a signature expires date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn set_signature_expires_at(&mut self, ts: i64) -> &mut Self {
        self.signature_expires = SignatureExpires::Absolute(ts);
        self
    }
    /// Ensures a signature expires date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn with_signature_expires_at(mut self, ts: i64) -> Self {
        self.signature_expires = SignatureExpires::Absolute(ts);
        self
    }
    /// Determines if a signature expires date will be added
    /// with a specific unix timestamp.
    ///
    /// This is off by default.
    pub fn signature_expires_at(&self) -> Option<i64> {
        if let SignatureExpires::Absolute(ts) = self.signature_expires {
            Some(ts)
        } else {
            None
        }
    }
}

/// Import this trait to get access to access the `signed` and `sign` methods on all types implementing
/// `ClientRequestLike`.
pub trait SigningExt: Sized {
    /// Consumes the request and returns it signed according to the provided configuration.
    fn signed(mut self, config: &SigningConfig) -> Result<Self, Error> {
        self.sign(config)?;
        Ok(self)
    }

    /// Signs the request in-place according to the provided configuration.
    fn sign(&mut self, config: &SigningConfig) -> Result<(), Error>;
}

fn add_auto_headers<R: ClientRequestLike>(
    request: &mut R,
    config: &SigningConfig,
) -> Vec<SignatureComponent> {
    // Add missing date header
    if config.add_date && !request.has_component(&DATE.into()) {
        let date = Utc::now().format(DATE_FORMAT).to_string();
        request.set_header(
            DATE,
            date.try_into()
                .expect("Dates should always be valid header values"),
        );
    }
    // Add missing host header
    if config.add_host && !request.has_component(&HOST.into()) {
        if let Some(host) = request.host() {
            request.set_header(
                HOST,
                host.try_into()
                    .expect("Host should be valid in a HTTP header"),
            );
        }
    }

    if config.compute_digest && !request.has_component(&digest_header().into()) {
        if let Some(digest_str) = request.compute_digest(&*config.digest) {
            let digest = format!("{}={}", config.digest.name(), digest_str);
            request.set_header(
                digest_header(),
                digest
                    .try_into()
                    .expect("Digest should be valid in a HTTP header"),
            );
        }
    }

    // Build the content block
    if config.skip_missing {
        config
            .components
            .iter()
            .filter(|header| request.has_component(header))
            .cloned()
            .collect()
    } else {
        config.components.clone()
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Unix time to be positive")
        .as_secs() as i64
}

impl<R: ClientRequestLike> SigningExt for R {
    fn sign(&mut self, config: &SigningConfig) -> Result<(), Error> {
        // Add missing components
        let components = add_auto_headers(self, config);

        let mut canonicalize_config = CanonicalizeConfig::new().with_components(components);

        canonicalize_config.set_alg(config.signature.name());

        // Verify the created and expires times are valid
        let ts = unix_timestamp();

        if let Some(created) = config.signature_created.get(ts) {
            if created > ts {
                return Err(Error::InvalidSignatureCreationDate);
            }
            canonicalize_config.set_created(created);
        }
        if let Some(expires) = config.signature_expires.get(ts) {
            if expires < ts {
                return Err(Error::InvalidSignatureExpiresDate);
            }
            canonicalize_config.set_expires(expires);
        }

        canonicalize_config.set_keyid(&config.key_id);

        if let Some(nonce) = config.nonce() {
            canonicalize_config.set_nonce(&nonce);
        }

        // Compute canonical signature base
        let (signature_base, signature_input) = self
            .canonicalize(&canonicalize_config)
            .map_err(|_| Error::Canonicalize)?;
        trace!(
            "Signing SignatureString: {}",
            &String::from_utf8(signature_base.clone()).unwrap()
        );

        // Attach the `signature-input` header to the request
        let signature_input_value = HeaderValue::from_str(signature_input.to_string().as_str())
            .map_err(|_| Error::SignatureInputError)?;

        self.set_header(signature_input_header(), signature_input_value);

        // Sign the content&
        let signature = config.signature.http_sign(&signature_base);
        let sig_header = format!("{}=:{}:", config.label, &signature);

        // Attach the signature header to the request
        self.set_header(
            signature_header(),
            sig_header
                .try_into()
                .expect("Signature should generate a valie header"),
        );

        Ok(())
    }
}
