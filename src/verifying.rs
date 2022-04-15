use log::trace;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, NaiveDateTime, Utc};
use http::header::DATE;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::{
    signature_header, signature_input_header, CanonicalizeConfig, CanonicalizeExt,
    DefaultDigestAlgorithm, HttpDigest, HttpSignatureVerify, RequestLike, SignatureComponent,
};

/// This error indicates that we failed to verify the request. As a result
/// the request should be ignored.
#[derive(Debug)]
#[non_exhaustive]
pub struct VerifyingError<Remnant> {
    remnant: Remnant,
}

impl<Remnant> VerifyingError<Remnant> {
    /// For some request types, the verification process may be a destructive operation.
    /// This method can be used to access information that would otherwise be lost as a
    /// result of the failed verification.
    pub fn into_remnant(self) -> Remnant {
        self.remnant
    }
}

impl<Remnant: Debug> Error for VerifyingError<Remnant> {}

impl<Remnant> Display for VerifyingError<Remnant> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("VerifyingError")
    }
}

/// The verification process will use this trait to find the appropriate key and algorithm
/// to use for verifying a request.
///
/// You do not need to implement this yourself: the `SimpleKeyProvider` type provides an
/// key store that should be suitable for many situations.
pub trait KeyProvider: Debug + Sync + 'static {
    /// Given the the key ID, return a set
    /// of possible keys. Returns an empty Vec if no appropriate key
    /// could be found.
    fn provide_keys(&self, key_id: &str) -> Vec<Arc<dyn HttpSignatureVerify>>;
}

/// Implementation of a simple key store.
///
/// Can store multiple keys.
/// If no algorithm is specified in the request, the first key added for
/// that Key ID will be used.
#[derive(Debug, Default, Clone)]
pub struct SimpleKeyProvider {
    keys: HashMap<String, Vec<Arc<dyn HttpSignatureVerify>>>,
}

impl SimpleKeyProvider {
    /// Initializes the key store from a list of key IDs and signature
    /// algorithms.
    pub fn new<I, S, K>(key_iter: I) -> Self
    where
        I: IntoIterator<Item = (S, K)>,
        S: Into<String>,
        K: Into<Arc<dyn HttpSignatureVerify>>,
    {
        let mut keys: HashMap<String, Vec<_>> = HashMap::new();
        for (key_id, key) in key_iter.into_iter() {
            keys.entry(key_id.into()).or_default().push(key.into());
        }
        Self { keys }
    }

    /// Adds a key to the key store
    pub fn add(&mut self, key_id: &str, key: Arc<dyn HttpSignatureVerify>) {
        self.keys.entry(key_id.into()).or_default().push(key);
    }
    /// Clears all keys from the key store
    pub fn clear(&mut self) {
        self.keys.clear();
    }
    /// Removes all keys with the specified Key ID from the key store
    pub fn remove_all(&mut self, key_id: &str) {
        self.keys.remove(key_id);
    }
}

impl KeyProvider for SimpleKeyProvider {
    fn provide_keys(&self, key_id: &str) -> Vec<Arc<dyn HttpSignatureVerify>> {
        self.keys.get(key_id).unwrap_or(&Vec::new()).to_vec()
    }
}

/// The verification process will use this trait to find the appropriate digest algorithm
/// to use when verifying the body of a request.
///
/// Unless explicitly overridden, the `DefaultDigestProvider` will be used
pub trait DigestProvider: Debug + Sync + 'static {
    /// Returns a digest algorithm for the given name, or `None` if the algorithm is not
    /// recognised by the provider.
    fn provide_digest(&self, name: &str) -> Option<Box<dyn HttpDigest>>;
}

/// Supports the `SHA-256` and `SHA-512` digest algorithms.
#[derive(Debug, Default, Copy, Clone)]
pub struct DefaultDigestProvider;

impl DigestProvider for DefaultDigestProvider {
    fn provide_digest(&self, name: &str) -> Option<Box<dyn HttpDigest>> {
        let name = name.to_ascii_uppercase();
        match name.as_str() {
            "SHA-256" => Some(Box::new(Sha256::new())),
            "SHA-512" => Some(Box::new(Sha512::new())),
            _ => None,
        }
    }
}

/// The configuration used for verifying HTTP requests.
#[derive(Debug)]
pub struct VerifyingConfig {
    key_provider: Arc<dyn KeyProvider>,
    digest_provider: Arc<dyn DigestProvider>,
    required_components: BTreeSet<SignatureComponent>,
    require_digest: bool,
    validate_digest: bool,
    validate_date: bool,
    date_leeway: Duration,
}

impl VerifyingConfig {
    /// Creates a new verifying configuration using the given key provider.
    pub fn new<KP: KeyProvider>(key_provider: KP) -> Self {
        VerifyingConfig {
            key_provider: Arc::new(key_provider),
            digest_provider: Arc::new(DefaultDigestProvider),
            required_components: BTreeSet::new(),
            require_digest: true,
            validate_digest: true,
            validate_date: true,
            date_leeway: Duration::from_secs(30),
        }
    }

    /// Returns the key provider.
    pub fn key_provider(&self) -> &dyn KeyProvider {
        &*self.key_provider
    }

    /// Returns the digest provider.
    pub fn digest_provider(&self) -> &dyn DigestProvider {
        &*self.digest_provider
    }

    /// Sets the digest provider (in-place).
    fn set_digest_provider<DP: DigestProvider>(&mut self, digest_provider: DP) -> &mut Self {
        self.digest_provider = Arc::new(digest_provider);
        self
    }

    /// Sets the digest provider.
    pub fn with_digest<DP: DigestProvider>(mut self, digest_provider: DP) -> Self {
        self.set_digest_provider(digest_provider);
        self
    }

    /// Returns whether a digest header must be present and included in the signature for requests
    /// with a body.
    ///
    /// This is set to `true` by default.
    pub fn require_digest(&self) -> bool {
        self.require_digest
    }

    /// Controls whether a digest header must be present and included in the signature for requests
    /// with a body (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_require_digest(&mut self, require_digest: bool) -> &mut Self {
        self.require_digest = require_digest;
        self
    }

    /// Controls whether a digest header must be present and included in the signature for requests
    /// with a body.
    ///
    /// This is set to `true` by default.
    pub fn with_require_digest(mut self, require_digest: bool) -> Self {
        self.set_require_digest(require_digest);
        self
    }

    /// Returns whether the request body will be checked against the digest for correctness if the
    /// digest is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn validate_digest(&self) -> bool {
        self.validate_digest
    }

    /// Controls whether the request body will be checked against the digest for correctness if the
    /// digest is included in the signature (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_validate_digest(&mut self, validate_digest: bool) -> &mut Self {
        self.validate_digest = validate_digest;
        self
    }

    /// Controls whether the request body will be checked against the digest for correctness if the
    /// digest is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn with_validate_digest(mut self, validate_digest: bool) -> Self {
        self.set_validate_digest(validate_digest);
        self
    }

    /// Returns whether the date header will be compared against the current date and time if the
    /// date header is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn validate_date(&self) -> bool {
        self.validate_date
    }

    /// Controls whether the date header will be compared against the current date and time if the
    /// date header is included in the signature (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_validate_date(&mut self, validate_date: bool) -> &mut Self {
        self.validate_date = validate_date;
        self
    }

    /// Controls whether the date header will be compared against the current date and time if the
    /// date header is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn with_validate_date(mut self, validate_date: bool) -> Self {
        self.set_validate_date(validate_date);
        self
    }

    /// Returns the amount of leeway allowed in either direction when comparing dates and times
    /// from requests against the current date and time.
    ///
    /// This is set to 30 seconds by default.
    pub fn date_leeway(&self) -> Duration {
        self.date_leeway
    }

    /// Controls the amount of leeway allowed in either direction when comparing dates and times
    /// from requests against the current date and time (in-place).
    ///
    /// This is set to 30 seconds by default.
    pub fn set_date_leeway(&mut self, date_leeway: Duration) -> &mut Self {
        self.date_leeway = date_leeway;
        self
    }

    /// Controls the amount of leeway allowed in either direction when comparing dates and times
    /// from requests against the current date and time.
    ///
    /// This is set to 30 seconds by default.
    pub fn with_date_leeway(mut self, date_leeway: Duration) -> Self {
        self.set_date_leeway(date_leeway);
        self
    }

    /// Returns the list of components that *must* be included in every request's signature. Do not
    /// include the `digest` header here or requests without a body will be denied. Instead, rely
    /// on the `validate_digest` option.
    ///
    /// This list contains `(request-target)` and `date` by default.
    pub fn required_components(&self) -> impl IntoIterator<Item = &SignatureComponent> {
        &self.required_components
    }

    /// Controls the list of components that *must* be included in every request's signature (in-place). Do not
    /// include the `digest` header here or requests without a body will be denied. Instead, rely
    /// on the `validate_digest` option.
    ///
    /// This list contains `(request-target)` and `date` by default.
    pub fn set_required_components(
        &mut self,
        required_components: &[SignatureComponent],
    ) -> &mut Self {
        self.required_components = required_components.iter().cloned().collect();
        self
    }

    /// Controls the list of components that *must* be included in every request's signature. Do not
    /// include the `digest` header here or requests without a body will be denied. Instead, rely
    /// on the `validate_digest` option.
    ///
    /// This list contains `(request-target)` and `date` by default.
    pub fn with_required_components(mut self, required_components: &[SignatureComponent]) -> Self {
        self.set_required_components(required_components);
        self
    }
}

/// This trait is to be implemented for types representing an incoming
/// HTTP request. The HTTP verification extension methods are available on
/// any type implementing this trait.
///
/// Typically this trait is implemented for references or mutable references to those
/// request types rather than for the request type itself.
pub trait ServerRequestLike: RequestLike {
    /// For some request types, the verification process may be a destructive operation.
    /// This associated type can be used to return information that might otherwise
    /// be lost.
    type Remnant;

    /// Complete the verification process, indicating that we want to compute a digest of the
    /// request body. This may require buffering the whole request body into memory.
    ///
    /// If a request body was present, its digest should be returned as the first element of
    /// the tuple. Otherwise `None` should be returned. The second tuple element may contain
    /// any information the implementation wants returned to the caller (for example the buffered
    /// request body, if it had to be removed from the request).
    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant);

    /// Complete the verification process without attempting to compute a digest.
    fn complete(self) -> Self::Remnant;
}

/// Contains information about a successfully validated request.
#[derive(Debug)]
pub struct VerificationDetails {
    key_id: String,
}

impl VerificationDetails {
    /// Returns the ID of the key used to validate this request's signature.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Import this trait to get access to access the `verify` method on all types implementing
/// `ServerRequestLike`.
pub trait VerifyingExt {
    /// For some request types, the verification process may be a destructive operation.
    /// This associated type can be used to return information that might otherwise
    /// be lost.
    type Remnant;

    /// Verify the request using the given verification configuration.
    fn verify(
        self,
        config: &VerifyingConfig,
    ) -> Result<(Self::Remnant, VerificationDetails), VerifyingError<Self::Remnant>>;
}

/// Parse the actual signature header, in the form of `<label>=:<signature>:`
fn parse_signature_header(signature_header: &str) -> Option<(&str, &str)> {
    let (label, signature) = signature_header.split_once('=').or_else(|| {
        info!("Verification Failed: Malformed 'Signature' header");
        None
    })?;
    let signature = signature.trim_matches(':');
    Some((label, signature))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Unix time to be positive")
        .as_secs() as i64
}

use crate::SignatureInput;
fn verify_signature_only<T: ServerRequestLike>(
    req: &T,
    config: &VerifyingConfig,
) -> Option<(SignatureInput, VerificationDetails)> {
    // The Signature and Signature-Input components contain all the info for
    // re-digesting and verifying the request signature
    let signature_input_value = req.derive(&signature_input_header().into()).or_else(|| {
        info!("Verification Failed: No 'Signature-Input' header");
        None
    })?;

    let canonicalize_config = CanonicalizeConfig::from_signature_input(&signature_input_value)
        .map_err(|e| {
            // Mapping the error here just provides an opportunity to trace
            info!("Verification Failed: Bad 'Signature-input' header");
            e
        })
        .ok()
        .unwrap();

    // Get the `signature` header, which has an sf dict value
    let signature_value = req.derive(&signature_header().into()).or_else(|| {
        info!("Verification Failed: Missing 'Signature' header");
        None
    })?;

    let (signature_label, provided_signature) = parse_signature_header(signature_value.as_str())
        .or_else(|| {
            info!("Verification Failed: Malformed 'Signature' header");
            None
        })?;

    // Match the labels
    let label = canonicalize_config.get_label();

    if !label.eq(signature_label) {
        info!("Verification Failed: Mismatched signature labels");
        return None;
    }

    let key_id = canonicalize_config.keyid().or_else(|| {
        info!("Verification Failed: Missing required 'keyid' in 'Signature-Input' header");
        None
    })?;

    let algorithm_name = canonicalize_config.alg().or_else(|| {
        info!("Verification Failed: Missing required 'alg' in 'Signature-Input' header");
        None
    })?;

    // Verify the created and expires times are valid
    let ts = unix_timestamp();

    if let Some(created) = canonicalize_config.created() {
        if created > ts {
            info!("Verification Failed: Bad created time");
            return None;
        }
    }

    if let Some(expires) = canonicalize_config.expires() {
        if expires < ts {
            info!("Verification Failed: Bad expires time");
            return None;
        }
    }

    let verification_details = VerificationDetails {
        key_id: key_id.to_owned(),
    };

    // Find the appropriate key
    let algorithms = config.key_provider.provide_keys(key_id);
    if algorithms.is_empty() {
        info!(
            "Verification Failed: Unknown key (keyId={}, algorithm={})",
            &key_id, &algorithm_name
        );
        return None;
    }

    // Canonicalize the request
    let (signature_base, signature_input) = req
        .canonicalize(&canonicalize_config)
        .map_err(|e| {
            info!("Canonicalization Failed: {}", e);
        })
        .ok()?;
    trace!(
        "Verifying SignatureString: {}",
        &String::from_utf8(signature_base.clone()).unwrap()
    );
    // Verify the signature of the content
    for algorithm in &algorithms {
        if algorithm.http_verify(&signature_base, provided_signature) {
            return Some((signature_input, verification_details));
        }
    }

    if algorithms.is_empty() {
        info!("Verification Failed: No keys found for this keyId");
    } else {
        info!("Verification Failed: Invalid signature provided");
    }
    None
}

fn verify_except_digest<T: ServerRequestLike>(
    req: &T,
    config: &VerifyingConfig,
) -> Option<VerificationDetails> {
    let (signature_input, verification_details) = verify_signature_only(req, config)?;

    // Check that all the required components are set
    for header in &config.required_components {
        if signature_input
            .list
            .get_item(header.to_string().as_ref())
            .is_none()
        {
            info!(
                "Verification Failed: Missing header '{}' required by configuration",
                header.to_string()
            );
            return None;
        }
    }

    // If we are expected to validate the date
    if config.validate_date() {
        // If date was part of signature
        let date_value = signature_input
            .get_param(DATE.to_string().as_ref())
            .and_then(|x| x.as_int())
            .or_else(|| {
                info!("Verification Failed: No DATE field in request");
                None
            })?;

        // Then parse into a datetime
        let provided_date = DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(date_value, 0), //  ::parse_from_str(date_value, DATE_FORMAT)
            Utc,
        );

        // Finally, compute the absolute difference between the provided
        // date and now.
        let chrono_delta = provided_date.signed_duration_since(Utc::now());
        let delta = chrono_delta
            .to_std()
            .or_else(|_| (-chrono_delta).to_std())
            .expect("Should only fail on negative values");

        if delta > config.date_leeway {
            info!(
                "Verification Failed: Date skew of '{}' is outside allowed range",
                chrono_delta
            );
            return None;
        }
    }

    Some(verification_details)
}

impl<T: ServerRequestLike> VerifyingExt for T {
    type Remnant = T::Remnant;

    fn verify(
        self,
        config: &VerifyingConfig,
    ) -> Result<(Self::Remnant, VerificationDetails), VerifyingError<Self::Remnant>> {
        // Check everything but the digest first, as that doesn't require consuming
        // the request.
        let verification_details = if let Some(res) = verify_except_digest(&self, config) {
            res
        } else {
            return Err(VerifyingError {
                remnant: self.complete(),
            });
        };

        // If the request has a digest header
        if let Some(digest_value) = self.derive(&crate::digest_header().into()) {
            // If we are expected to validate it
            if config.validate_digest {
                // Find the first digest which is using a supported algorithm
                if let Some((digest_alg, provided_digest)) = digest_value
                    .split(',')
                    .filter_map(|part| {
                        let mut kv = part.splitn(2, '=');
                        let k = kv.next()?.trim();
                        let v = kv.next()?.trim();

                        let digest = config.digest_provider.provide_digest(k)?;
                        Some((digest, v))
                    })
                    .next()
                {
                    // Tell the request to compute a digest as it completes
                    let (maybe_digest, remnant) = self.complete_with_digest(&*digest_alg);

                    // Check that the digest is correct in constant time
                    match maybe_digest {
                        Some(expected_digest)
                            if provided_digest
                                .as_bytes()
                                .ct_eq(expected_digest.as_bytes())
                                .into() =>
                        {
                            Ok((remnant, verification_details))
                        }
                        None => {
                            info!("Verification Failed: Unable to compute digest for comparison");
                            Err(VerifyingError { remnant })
                        }
                        _ => {
                            info!("Verification Failed: Computed digest did not match the 'digest' header");
                            Err(VerifyingError { remnant })
                        }
                    }
                } else {
                    // No supported digest algorithm.
                    info!("Verification Failed: No supported digest algorithms were used");
                    Err(VerifyingError {
                        remnant: self.complete(),
                    })
                }
            } else {
                // We are not expected to validate the digest
                Ok((self.complete(), verification_details))
            }
        } else if config.require_digest {
            // We require a digest for requests with a body, but we didn't get one. Either the request
            // has no body, or we should reject it.
            let (maybe_digest, remnant) = self.complete_with_digest(&DefaultDigestAlgorithm::new());

            // If the request did have a body (because we were able to compute a digest).
            if maybe_digest.is_some() {
                // Then reject the request
                info!("Verification Failed: 'digest' header was not included in signature, but is required by configuration");
                Err(VerifyingError { remnant })
            } else {
                // No body, so request if fine.
                Ok((remnant, verification_details))
            }
        } else {
            // We do not require a digest, valid or otherwise.
            Ok((self.complete(), verification_details))
        }
    }
}
