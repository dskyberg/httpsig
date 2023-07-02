use http::{
    header::{HeaderName, HeaderValue},
    Method,
};

use super::*;

/// Consolidated
fn handle_derived_component(
    component: &DerivedComponent,
    host: Option<String>,
    method: &Method,
    url: &url::Url,
) -> Option<String> {
    match component.name() {
        AT_METHOD => Some(method.to_string()),
        // Reqwest does not support relative urls.  So, entire
        // url is the request target.
        AT_REQUEST_TARGET => Some(url.to_string()),
        AT_TARGET_URI => Some(url.to_string()),
        // In a request, @authority is the HOST
        AT_AUTHORITY => host,
        AT_SCHEME => Some(url.scheme().to_string()),
        AT_PATH => Some(url.path().to_string()),
        AT_QUERY => url.query().map(|query| format!("?{}", query.to_owned())),
        AT_QUERY_PARAMS => {
            // A query-param component must have a parameter. The param key must be "name".
            let dqp_field = component.param("name")?;

            // Get the parameter field name.
            let mut derived: Vec<String> = Vec::new();
            let qp_pairs = url.query_pairs();
            for (qp_name, qp_value) in qp_pairs {
                if dqp_field.eq(&qp_name) {
                    // Construct a signature base entry for each instance of the
                    derived.push(format!("{}", qp_value));
                }
            }
            Some(derived.join("\n"))
        }
        _ => None,
    }
}

impl RequestLike for reqwest::Request {
    fn derive(&self, component: &SignatureComponent) -> Option<String> {
        match component {
            SignatureComponent::Header(header_name) => self
                .headers()
                .get(header_name)
                .and_then(|value| value.to_str().ok())
                .map(|x| x.to_string()),

            SignatureComponent::Derived(component) => {
                handle_derived_component(component, self.host(), self.method(), self.url())
            }
        }
    }

    fn has_component(&self, component: &SignatureComponent) -> bool {
        self.derive(component).is_some()
    }
}

impl ClientRequestLike for reqwest::Request {
    fn host(&self) -> Option<String> {
        self.url().host_str().map(Into::into)
    }
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        self.body()?.as_bytes().map(|b| digest.http_digest(b))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

impl RequestLike for reqwest::blocking::Request {
    fn derive(&self, component: &SignatureComponent) -> Option<String> {
        match component {
            SignatureComponent::Header(header_name) => self
                .headers()
                .get(header_name)
                .and_then(|value| value.to_str().ok())
                .map(|x| x.to_string()),

            SignatureComponent::Derived(component) => {
                handle_derived_component(component, self.host(), self.method(), self.url())
            }
        }
    }

    fn has_component(&self, component: &SignatureComponent) -> bool {
        self.derive(component).is_some()
    }
}

impl ClientRequestLike for reqwest::blocking::Request {
    fn host(&self) -> Option<String> {
        self.url().host_str().map(Into::into)
    }
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        let bytes_to_digest = self.body_mut().as_mut()?.buffer().ok()?;
        Some(digest.http_digest(bytes_to_digest))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

impl Derivable<DerivedComponent> for reqwest::Request {
    fn derive_component(&self, component: &DerivedComponent) -> Option<String> {
        handle_derived_component(component, self.host(), self.method(), self.url())
    }
}

impl Derivable<DerivedComponent> for reqwest::blocking::Request {
    fn derive_component(&self, component: &DerivedComponent) -> Option<String> {
        handle_derived_component(component, self.host(), self.method(), self.url())
    }
}

#[cfg_attr(not(feature = "reqwest"), ignore)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::AT_REQUEST_TARGET;
    use chrono::{offset::TimeZone, Utc};
    use http::header::{CONTENT_TYPE, DATE, HOST};

    fn request(url: &str) -> reqwest::Request {
        reqwest::Client::new().post(url).build().unwrap()
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
        let request_target = "value";
        let dqp = DerivedComponent::new(AT_QUERY_PARAMS).with_param("name", "param");
        let result = request(url)
            .derive(&SignatureComponent::Derived(dqp))
            .unwrap();
        assert_eq!(request_target, result);
    }

    #[test]
    fn it_works() {
        let components = [
            SignatureComponent::Derived(DerivedComponent::new(AT_REQUEST_TARGET)),
            SignatureComponent::Header(DATE),
            SignatureComponent::Header(HeaderName::from_static("digest")),
            SignatureComponent::Header(HOST),
        ]
        .to_vec();
        //let key = include_bytes!("../test_data/rsa-private.pem");
        //let signature_alg = RsaSha256Sign::new_pkcs8_pem(key).expect("Failed to create key");
        let key = "password".as_bytes();
        let signature_alg = HmacSha256::new(key);
        let sign_config =
            SigningConfig::new("sig", "hmac", signature_alg).with_components(&components);

        let client = reqwest::Client::new();

        let without_sig = client
            .post("https://example.com/foo?param=value&pet=dog")
            .header(HOST, "example.com")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.with_ymd_and_hms(2021, 4, 20, 2, 7, 55)
                    .unwrap()
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .header(
                "DIGEST",
                "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
            )
            .header("Example-Dict", "a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid")
            .body(&br#"{"hello": "world"}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&sign_config).unwrap();

        assert_eq!(
            with_sig.headers().get(signature_input_header()).unwrap(),
            r#"sig=("@request-target" "date" "digest" "host");alg="hmac-sha256";keyid="hmac""#
        );
        assert_eq!(
            with_sig.headers().get(signature_header()).unwrap(),
            "sig=:3YquZWmc8X0QnicPjncUr9vjS1FXEkFGY7+QtWNJtVc=:"
        );
    }
}
