#![doc = include_str!("../README.md")]

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use error::AppError;
//use http_sig::mock_request::MockRequest;
use httpsig::{
    CanonicalizeConfig, CanonicalizeExt, RsaPssSha256Sign, RsaPssSha256Verify, RsaPssSha512Sign,
    RsaPssSha512Verify, RsaSha256Sign, RsaSha256Verify, RsaSha512Sign, RsaSha512Verify,
    SignatureComponent, SigningConfig, SigningExt, SimpleKeyProvider, VerifyingConfig,
    VerifyingExt,
};
use structopt::StructOpt;

mod error;
mod mock_request;
use mock_request::MockRequest;

#[derive(Debug, StructOpt)]
enum Mode {
    Canonicalize,
    Sign,
    Verify,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "A validator for use with the HTTP-signatures test suite.")]
struct Opt {
    /// A list of header names, optionally quoted
    #[structopt(subcommand)]
    mode: Mode,

    /// Input file.  Default is stdin.
    #[structopt(short, long = "in", global = true)]
    in_file: Option<String>,

    /// A list of header names, optionally quoted
    #[allow(clippy::option_option)]
    #[structopt(short = "d", long, global = true, min_values = 0)]
    headers: Option<Option<String>>,

    /// A Key Id string.
    #[structopt(short, long = "keyId", global = true)]
    key_id: Option<String>,

    /// A private key file name filename.
    #[structopt(short, long, parse(from_os_str), global = true)]
    private_key: Option<PathBuf>,

    /// A public key file name filename.
    #[structopt(short = "u", long, parse(from_os_str), global = true)]
    public_key: Option<PathBuf>,

    /// Signature label to use
    #[structopt(short, long, global = true)]
    label: Option<String>,

    /// One of: rsa-v1_5-sha256, rsa-v1_5-sha512, rsa-pss-sha256, rsa-pss-sha512, hmac-sha256, hmac-sha512
    #[structopt(short, long, global = true)]
    algorithm: Option<String>,

    /// The created param for the signature.
    #[structopt(short, long, global = true)]
    created: Option<i64>,

    /// The expires param for the signature.
    #[structopt(short, long, global = true)]
    expires: Option<i64>,

    /// The nonce to use for signing
    #[structopt(short, long, global = true)]
    nonce: Option<String>,
}

impl Opt {
    fn parse_headers(&self) -> Result<Option<Vec<SignatureComponent>>, Box<dyn Error>> {
        Ok(if let Some(headers) = &self.headers {
            Some(if let Some(headers) = headers {
                let headers: Vec<SignatureComponent> = headers
                    .split_ascii_whitespace()
                    .map(|s| s.parse::<SignatureComponent>())
                    .collect::<Result<_, _>>()?;
                headers
            } else {
                Vec::new()
            })
        } else {
            None
        })
    }

    fn canonicalize_config(&self) -> Result<CanonicalizeConfig, Box<dyn Error>> {
        let mut config = CanonicalizeConfig::default();
        if let Some(created) = self.created {
            config.set_created(created);
        }
        if let Some(expires) = self.expires {
            config.set_expires(expires);
        }
        if let Some(components) = self.parse_headers()? {
            config.set_components(components);
        }
        if let Some(nonce) = self.nonce.as_deref() {
            config.set_nonce(nonce);
        }
        if let Some(label) = self.label.as_deref() {
            config.set_label(label);
        }
        if let Some(key_id) = self.key_id.as_deref() {
            config.set_keyid(key_id);
        }

        match self.algorithm.as_deref() {
            Some("rsa-v1_5-sha256")
            | Some("rsa-v1_5-sha512")
            | Some("rsa-pss-sha256")
            | Some("rsa-pss-sha512")
            | Some("ecdsa-p256-sha256")
            | Some("hmac-sha256") => config.set_alg(self.algorithm.as_deref().unwrap()),
            Some(other) => {
                return Err(Box::new(AppError::BadArg(format!(
                    "Unknown algorithm: {}",
                    other
                ))))
            } // Err(Box::new(AppError::BadArg("Unknown algorithm: {}", other).into()),
            None => {
                return Err(Box::new(AppError::BadArg(
                    "No algorithm provided".to_string(),
                )))
            }
        }

        match self.parse_headers()? {
            Some(components) => {
                config.set_components(components);
            }
            None => {
                config.set_components(Vec::new());
            }
        }

        Ok(config)
    }

    fn signing_config(&self) -> Result<SigningConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        let label = self.label.clone().unwrap_or_else(|| "sig".to_owned());

        let key_data = if let Some(key) = self.private_key.as_ref() {
            Some(fs::read(key)?)
        } else {
            None
        };

        match self.algorithm.as_deref() {
            Some("rsa-pss-sha256")
            | Some("rsa-pss-sha512")
            | Some("rsa-v1_5-sha256")
            | Some("rsa-v1_5-sha512")
            | Some("hmac-sha256")
            | Some("ecdsa-p256-sha256")
            | None => {}
            Some(other) => {
                return Err(Box::new(AppError::BadArg(format!(
                    "Unknown algorithm: {}",
                    other
                ))))
            }
        }

        let mut config = match (self.algorithm.as_deref(), key_data) {
            (Some("rsa-v1_5-sha256"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaSha256Sign::new_pkcs8_pem(&pkey)?)
            }
            (Some("rsa-v1_5-sha512"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaSha512Sign::new_pkcs8_pem(&pkey)?)
            }
            (Some("rsa-pss-sha256"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaPssSha256Sign::new_pkcs8_pem(&pkey)?)
            }
            (Some("rsa-pss-sha512"), Some(pkey)) => {
                SigningConfig::new(&label, &key_id, RsaPssSha512Sign::new_pkcs8_pem(&pkey)?)
            }
            (Some(_), None) => {
                return Err(Box::new(AppError::BadArg("No key provided".to_string())))
            }
            (Some(other), Some(_)) => {
                return Err(Box::new(AppError::BadArg(format!(
                    "Unsupported algorithm: {}",
                    other
                ))))
            }
            (None, _) => {
                return Err(Box::new(AppError::BadArg(
                    "No algorithm provided".to_string(),
                )))
            }
        };

        if let Some(components) = self.parse_headers()? {
            config.set_components(&components);
        }

        if let Some(created) = self.created {
            config.set_signature_created_at(created);
        }

        if let Some(expires) = self.expires {
            config.set_signature_expires_at(expires);
        }

        // Disable various convenience options that would mess up the test suite
        config.set_add_date(false);
        config.set_compute_digest(false);
        config.set_add_host(false);
        config.set_skip_missing(false);

        Ok(config)
    }

    fn verification_config(&self) -> Result<VerifyingConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        log::trace!("Using key_id: {}", &key_id);
        let key_data = if let Some(key) = self.public_key.as_ref() {
            log::trace!("Reading public key from file");
            Some(fs::read(key)?)
        } else {
            log::trace!("No public key was read.  This is bad.");
            None
        };

        let mut key_provider = SimpleKeyProvider::default();

        match self.algorithm.as_deref() {
            Some("rsa-pss-sha256")
            | Some("rsa-pss-sha512")
            | Some("rsa-v1_5-sha256")
            | Some("rsa-v1_5-sha512")
            | Some("hmac-sha256")
            | Some("ecdsa-p256-sha256")
            | None => {}
            Some(other) => {
                return Err(Box::new(AppError::BadArg(format!(
                    "Unknown algorithm: {}",
                    other
                ))))
            }
        };
        if self.algorithm.is_none() {
            log::trace!("No recognized algorithm was provided");
        }

        match (self.algorithm.as_deref(), key_data) {
            (Some("rsa-v1_5-sha256"), Some(pkey)) => {
                log::trace!("Loading rsa-v1_5-sha256");
                let mut key = RsaSha256Verify::new_spki_pem(&pkey);
                if key.is_err() {
                    log::trace!("Not an SPKI formatted key.  Trying PKCS1");
                    key = RsaSha256Verify::new_pkcs1_pem(&pkey);
                }
                let key = key?;
                key_provider.add(&key_id, Arc::new(key))
            }
            (Some("rsa-v1_5-sha512"), Some(pkey)) => {
                log::trace!("Loading rsa-v1_5-sha512");
                key_provider.add(&key_id, Arc::new(RsaSha512Verify::new_pkcs1_pem(&pkey)?))
            }

            (Some("rsa-pss-sha256"), Some(pkey)) => {
                log::trace!("Loading rsa-pss-sha256");
                key_provider.add(&key_id, Arc::new(RsaPssSha256Verify::new_pkcs1_pem(&pkey)?))
            }
            (Some("rsa-pss-sha512"), Some(pkey)) => {
                log::trace!("Loading rsa-pss-sha512");
                key_provider.add(&key_id, Arc::new(RsaPssSha512Verify::new_pkcs1_pem(&pkey)?))
            }
            (Some(_), None) => {
                log::trace!("No key provided");
                return Err(Box::new(AppError::BadArg("No key provided".to_string())));
            }
            (Some(other), Some(_)) => {
                return Err(Box::new(AppError::BadArg(format!(
                    "Unknown key type: {}",
                    other
                ))))
            }
            (None, _) => {
                log::trace!("No key was loaded");
            }
        };

        let mut config = VerifyingConfig::new(key_provider);

        // Disable various convenience options that would mess up the test suite
        config.set_require_digest(false);
        config.set_validate_date(false);
        //config.set_required_headers(&[]);

        Ok(config)
    }
}

use std::fs::File;
use std::io::BufReader;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let opt = Opt::from_args();

    // Create the MocRequest either from a provided file or from stdin
    let mut req = if let Some(ref filename) = opt.in_file {
        let f = File::open(filename).expect("Failed to open file");
        let mut reader = BufReader::new(f);
        MockRequest::from_reader(&mut reader).expect("Failed to read request from file")
    } else {
        MockRequest::from_reader(&mut io::stdin().lock())
            .expect("Failed to read request from stdin")
    };

    log::trace!("{:#?}", req);
    match opt.mode {
        Mode::Canonicalize => {
            let (res, _signature_input) = req.canonicalize(&opt.canonicalize_config()?)?;
            io::stdout().lock().write_all(&res)?;
        }
        Mode::Sign => {
            req.sign(&opt.signing_config()?)?;
            req.write(&mut io::stdout().lock())?;
        }
        Mode::Verify => {
            let config = opt.verification_config()?;
            req.verify(&config)?;
        }
    }

    Ok(())
}
