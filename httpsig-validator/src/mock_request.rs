use std::collections::HashMap;
use std::io::{BufRead, Write};

use crate::error::AppError;

use httpsig::url::ParseError;
use httpsig::{
    http::{header::HeaderName, HeaderValue, Method},
    url::Url,
    ClientRequestLike, Derivable, DerivedComponent, HttpDigest, RequestLike, ServerRequestLike,
    SignatureComponent, AT_AUTHORITY, AT_METHOD, AT_PATH, AT_QUERY, AT_QUERY_PARAMS,
    AT_REQUEST_TARGET, AT_SCHEME, AT_TARGET_URI,
};

/// A mock request type
///
/// MockRequest provides an example of how to fulfill the [RequestLike], [ClientRequestLike],
/// [ServerRequestLike], and [Derivable] traits.  Use this as a template to extend to your
/// target request crate.
#[derive(Debug, Clone, PartialEq)]
pub struct MockRequest {
    method: Method,
    url: Url,
    path: String,
    headers: HashMap<HeaderName, HeaderValue>,
    body: Option<Vec<u8>>,
}

impl MockRequest {
    /// Returns the method used by this mock request
    pub fn method(&self) -> Method {
        self.method.clone()
    }
    /// Returns the path used by this mock request
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Original path from request
    pub fn path(&self) -> &String {
        &self.path
    }
    /// Returns the headers used by this mock request
    pub fn headers(&self) -> impl IntoIterator<Item = (&HeaderName, &HeaderValue)> {
        &self.headers
    }

    /// Check if a header is set
    pub fn has_header(&self, name: &HeaderName) -> bool {
        self.headers.get(name).is_some()
    }

    /// return a header
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    /// Returns the body used by this mock request
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Constructs a new mock request
    pub fn new(method: Method, path: &str) -> Self {
        let url: Url = path.parse().unwrap();
        let mut res = Self {
            method,
            url: path.parse().unwrap(),
            path: path.to_string(),
            headers: Default::default(),
            body: None,
        };

        let host_str = url.host_str();
        if let Some(host) = host_str {
            res = res.with_header("Host", host)
        }

        res
    }

    /// Convenience method for setting a header
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.set_header(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
        self
    }

    /// Method for setting a request body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        let l = body.len();
        self.body = Some(body);
        self.with_header("Content-Length", &l.to_string())
    }

    /// Parse a HTTP request into this mock request object
    pub fn from_reader<R: BufRead>(reader: &mut R) -> Result<Self, Box<dyn std::error::Error>> {
        let mut line = String::new();

        // Read request line
        reader.read_line(&mut line)?;
        let mut parts = line.split_ascii_whitespace();

        // Extract method
        let method: Method = parts.next().ok_or(AppError::ParseError)?.parse()?;

        // Extract method
        let path: String = parts.next().ok_or(AppError::ParseError)?.parse()?;

        // Extract headers
        #[allow(clippy::mutable_key_type)]
        let mut headers = HashMap::new();

        let has_body = loop {
            line.truncate(0);
            if reader.read_line(&mut line)? == 0 {
                break false;
            }
            if line.trim().is_empty() {
                break true;
            }

            let mut parts = line.splitn(2, ':');

            let name_str = parts.next().ok_or(httpsig::Error::ParseError)?.trim();
            let header_name: HeaderName = name_str.parse()?;
            let value_str = parts.next().ok_or(httpsig::Error::ParseError)?.trim();
            let header_value: HeaderValue = value_str.parse()?;
            headers.insert(header_name, header_value);
        };

        let body = if has_body {
            let mut body = Vec::new();
            reader.read_to_end(&mut body)?;
            log::trace!(
                "Messge Body: {}",
                &String::from_utf8(body.clone()).expect("Failed to convert from [u8] to String")
            );
            Some(body)
        } else {
            None
        };

        // log::trace!("Headers: {:?}", &headers);

        // See if the url is relative.  If so, let's try to fix it up.
        let url = Self::derive_url(&path, None, &headers)?;

        Ok(Self {
            method,
            url,
            path,
            headers,
            body,
        })
    }

    /// Derive an absolute URL from request components
    /// The [httpsig::url] create does not support relative URLs.
    ///
    /// If no HOST header is available, then this method wil fail.
    #[allow(clippy::mutable_key_type)]
    fn derive_url(
        path: &str,
        schema: Option<&str>,
        headers: &HashMap<HeaderName, HeaderValue>,
    ) -> Result<Url, Box<dyn std::error::Error>> {
        // See if the url is relative.  If so, let's try to fix it up.
        let url: Result<Url, Box<dyn std::error::Error>> = match path.parse() {
            Ok(u) => Ok(u),
            Err(ParseError::RelativeUrlWithoutBase) => {
                // It's a relative URL.  So, we need to prepen the schema and authority
                let schema = schema.unwrap_or("http");
                match headers.get(&HeaderName::from_static("host")) {
                    Some(host) => {
                        log::trace!("Attempting to use host header");
                        Ok(format!("{}://{}{}", schema, host.to_str()?, path)
                            .parse()
                            .expect("still failed!!"))
                    }
                    None => {
                        log::info!("Cannot use relative URLs: {}", &path);
                        Err(Box::new(ParseError::RelativeUrlWithoutBase))
                    }
                }
            }
            Err(e) => Err(Box::new(e)),
        };

        url
    }

    /// Write out this HTTP request in standard format
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn std::error::Error>> {
        writeln!(writer, "{} {} HTTP/1.1", self.method.as_str(), self.path())?;
        for (header_name, header_value) in &self.headers {
            writeln!(
                writer,
                "{}: {}",
                header_name.as_str(),
                header_value.to_str()?
            )?;
        }

        if let Some(body) = &self.body {
            writeln!(writer)?;
            writer.write_all(body)?;
        }

        Ok(())
    }
}

impl Derivable<DerivedComponent> for MockRequest {
    /// Deriveable for MockRequest
    fn derive_component(&self, component: &DerivedComponent) -> Option<String> {
        match component.name() {
            // Given POST https://www.method.com/path?param=value
            // target uri = POST
            AT_METHOD => Some(self.method().as_str().to_owned()),

            // Given POST https://www.method.com/path?param=value
            // target uri = https://www.method.com/path?param=value
            AT_TARGET_URI => Some(self.url().to_string()),

            // Given POST https://www.method.com/path?param=value
            // target uri = www.method.com
            AT_AUTHORITY => self.url().host_str().map(|s| s.to_owned()),

            // Given POST https://www.method.com/path?param=value
            // target uri = https
            AT_SCHEME => Some(self.url().scheme().to_owned()),

            // given POST https://www.example.com/path?param=value
            // request target = /path
            AT_REQUEST_TARGET => Some(self.url().to_string()),

            // given POST https://www.example.com/path?param=value
            // request target = /path?param=value
            AT_PATH => Some(self.url().path().to_owned()),

            // given POST https://www.example.com/path?param=value&foo=bar&baz=batman
            // request target = /path?param=value
            AT_QUERY => self.url().query().map(|s| format!("?{}", s.to_owned())),

            AT_QUERY_PARAMS => {
                // A query-param component must have a parameter. The param key must be "name".
                let dqp_field = component.param("name")?;

                // Get the parameter field name
                let mut derived: Vec<String> = Vec::new();
                let qp_pairs = self.url.query_pairs();
                for (qp_name, qp_value) in qp_pairs {
                    if dqp_field.eq(&qp_name) {
                        // Construct a signature base entry for each instance
                        derived.push(format!("{}", qp_value));
                    }
                }
                Some(derived.join("\n"))
            }
            _ => None,
        }
    }
}

impl RequestLike for MockRequest {
    /// Return a value for standard headers, or a canonicalized Derived Component.
    fn derive(&self, component: &SignatureComponent) -> Option<String> {
        match component {
            // Either return a standard Header,
            SignatureComponent::Header(header_name) => self
                .headers
                .get(header_name)
                .map(|value| value.to_str().unwrap_or_default().to_string()),
            // Or a Derived Component,
            SignatureComponent::Derived(component) => self.derive_component(component),
        }
    }

    fn has_component(&self, component: &SignatureComponent) -> bool {
        self.derive(component).is_some()
    }
}

impl ClientRequestLike for MockRequest {
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        self.body.as_ref().map(|b| digest.http_digest(b))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers.insert(header, value);
    }
}

impl<'a> ServerRequestLike for &'a MockRequest {
    type Remnant = ();

    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant) {
        if let Some(body) = self.body.as_ref() {
            let computed_digest = digest.http_digest(body);
            (Some(computed_digest), ())
        } else {
            (None, ())
        }
    }
    fn complete(self) -> Self::Remnant {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningConfig, SigningExt};
    use httpsig::http::header::{DATE, HOST};

    use std::sync::Arc;

    use httpsig::{
        EcdsaP256Sha256Sign, EcdsaP256Sha256Verify, HttpSignatureVerify, RsaSha256Sign,
        RsaSha256Verify, SimpleKeyProvider, VerifyingConfig, VerifyingExt, AT_AUTHORITY, AT_METHOD,
        AT_PATH, AT_QUERY, AT_QUERY_PARAMS, AT_REQUEST_TARGET, AT_SCHEME, AT_TARGET_URI,
    };

    fn request(url: &str) -> MockRequest {
        MockRequest::new(Method::POST, url)
    }

    #[test]
    fn test_derive_method() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "POST";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(
                AT_METHOD,
            )))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_target_uri() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "https://www.example.com/path?param=value";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(
                AT_TARGET_URI,
            )))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_authority() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "www.example.com";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(
                AT_AUTHORITY,
            )))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_scheme() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "https";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(
                AT_SCHEME,
            )))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_request_target() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "https://www.example.com/path?param=value";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(
                AT_REQUEST_TARGET,
            )))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_path() {
        let url = "https://www.example.com/path?param=value";
        let request_target = "/path";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(AT_PATH)))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_query() {
        let url = "https://www.example.com//path?param=value&foo=bar&baz=batman";
        let request_target = "?param=value&foo=bar&baz=batman";
        let result = request(url)
            .derive(&SignatureComponent::Derived(DerivedComponent::new(
                AT_QUERY,
            )))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn test_derive_query_params() {
        let url = "https://www.example.com//path?param=value&foo=bar&baz=batman";
        let dqp = DerivedComponent::new(AT_QUERY_PARAMS).with_param("name", "param");
        let result = request(url)
            .derive(&SignatureComponent::Derived(dqp))
            .unwrap();
        assert_eq!(result, "value");
    }

    pub fn test_request(filename: &str) -> MockRequest {
        use std::fs::File;
        use std::io::BufReader;

        let f = File::open(filename).expect("Failed to open file");
        let mut reader = BufReader::new(f);

        MockRequest::from_reader(&mut reader).expect("Failed to read request")
    }

    /// Test key as defined in the draft specification:
    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.appendix.C
    fn test_key_provider() -> SimpleKeyProvider {
        SimpleKeyProvider::new(vec![
            (
                "test-key-rsa",
                Arc::new(
                    RsaSha256Verify::new_pem(include_bytes!("../../test_data/rsa-public.pem"))
                        .unwrap(),
                ) as Arc<dyn HttpSignatureVerify>,
            ),
            (
                "test-key-ecdsa",
                Arc::new(
                    EcdsaP256Sha256Verify::new_pem(include_bytes!(
                        "../../test_data/ecc-public.pem"
                    ))
                    .unwrap(),
                ) as Arc<dyn HttpSignatureVerify>,
            ),
        ])
    }

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#default-test
    /// This test is currently broken in the spec, so it's been adjusted to pass...
    #[test]
    fn rsa_test() {
        // Expect successful validation
        let test_req_filename = "../test_data/basic_request.txt";
        let key = include_bytes!("../../test_data/rsa-private.pem");
        let signature_alg = RsaSha256Sign::new_pkcs8_pem(key).expect("Failed to create key");
        let dqp = DerivedComponent::new(AT_QUERY_PARAMS).with_param("name", "param");
        // Declare the headers to be included in the signature.
        // NOTE: NO HEADERS ARE INCLUDED BY DEFAULT
        let headers = [
            SignatureComponent::Header(HOST),
            SignatureComponent::Header(DATE),
            SignatureComponent::Header(HeaderName::from_static("digest")),
            SignatureComponent::Derived(DerivedComponent::new(AT_REQUEST_TARGET)),
            SignatureComponent::Derived(dqp),
        ]
        .to_vec();

        let sign_config = SigningConfig::new("sig", "test-key-rsa", signature_alg)
            .with_components(&headers)
            .with_add_date(true);

        let mut req = test_request(test_req_filename)
            .signed(&sign_config)
            .expect("Failed to sign");

        dbg!(&req);
        let mut verify_config = VerifyingConfig::new(test_key_provider()).with_validate_date(true);
        // Because the test_request has a fixed date in the past...
        verify_config.set_validate_date(false);

        let result = req.verify(&verify_config);
        assert!(result.is_ok());
        // Expect failing validation
        req = req.with_header("Date", "Sun, 05 Jan 2014 21:31:41 GMT");

        let result = req.verify(&verify_config);
        assert!(result.is_err());
    }

    /// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#default-test
    #[test]
    fn ecdsa_test() {
        let test_req_filename = "../test_data/basic_request.txt";

        // Expect successful validation
        let key = include_bytes!("../../test_data/ecc-private.pem");
        let signature_alg = EcdsaP256Sha256Sign::new_pkcs8_pem(key).expect("Failed to create key");
        // Declare the headers to be included in the signature.
        // NOTE: NO HEADERS ARE INCLUDED BY DEFAULT
        let headers = [
            SignatureComponent::Header(HOST),
            SignatureComponent::Header(DATE),
            SignatureComponent::Header(HeaderName::from_static("digest")),
        ]
        .to_vec();

        let sign_config = SigningConfig::new("sig", "test-key-ecdsa", signature_alg)
            .with_components(&headers)
            .with_add_date(true);

        //dbg!(&sign_config);
        let mut req = test_request(test_req_filename)
            .signed(&sign_config)
            .expect("Failed to sign");
        //dbg!(&req);
        let mut verify_config = VerifyingConfig::new(test_key_provider());
        // Because the test_request has a fixed date in the past...
        verify_config.set_validate_date(false);

        let result = req.verify(&verify_config);
        assert!(result.is_ok());
        // Expect failing validation
        req = req.with_header("Date", "Sun, 05 Jan 2014 21:31:41 GMT");

        let result = req.verify(&verify_config);
        assert!(result.is_err());
    }

    #[test]
    fn no_headers() {
        let test_req_filename = "../test_data/basic_request.txt";

        // In leiu of a true const value for the header:
        let signature_input_header = HeaderName::from_static("signature-input");
        // The "Signature-Input" value should have no headers:
        let test_val = r#"sig=();alg="rsa-v1_5-sha256";keyid="test-key-rsa""#;

        let key = include_bytes!("../../test_data/rsa-private.pem");
        let signature_alg = RsaSha256Sign::new_pkcs8_pem(key).expect("Failed to create key");

        // Turn off all automatic headers, like host, date, and digest
        let sign_config =
            SigningConfig::new("sig", "test-key-rsa", signature_alg).with_compute_digest(false);

        // Create the signed request
        let req = test_request(test_req_filename)
            .signed(&sign_config)
            .expect("Failed to sign");
        // dbg!(&req);
        // Get the Signature-Input header value as an &str
        let header_val = req.header(&signature_input_header).unwrap();
        let header_val = header_val.to_str().unwrap();

        assert_eq!(&test_val, &header_val);
    }
}
