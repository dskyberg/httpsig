//use pem;
use base64::{engine::general_purpose, Engine as _};
use ring::{rand, signature};
use spki::SubjectPublicKeyInfoRef;

use crate::{HttpSignatureSign, HttpSignatureVerify};

macro_rules! rsa_signature {
    ({$sign_name:ident($sign_alg:ident), $verify_name:ident($verify_alg:ident)} = $name:literal) => {
        #[doc = "Implementation of the signing half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $sign_name(signature::RsaKeyPair);

        #[doc = "Implementation of the verification half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $verify_name(Vec<u8>);

        impl $sign_name {
            /// Create a new instance of the signature scheme using the
            /// provided private key in standard PKCS8 DER format.
            pub fn new_pkcs8(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(signature::RsaKeyPair::from_pkcs8(private_key)?))
            }

            /// Create a new instance of the signature scheme using the
            /// provided private key in standard PKCS8 PEM format.
            /// PKCS8 files begin with
            /// -----BEGIN PRIVATE KEY-----
            pub fn new_pkcs8_pem(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let bytes = pem::parse(private_key)?;
                Ok(Self(signature::RsaKeyPair::from_pkcs8(&bytes.contents)?))
            }
            /// Create a new instance of the signature scheme using the
            /// provided private key in RSAPrivateKey (PKCS1) DER format.
            pub fn new_pkcs1(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(signature::RsaKeyPair::from_der(private_key)?))
            }
            /// Create a new instance of the signature scheme using the
            /// provided private key in RSAPrivateKey (PKCS1) PEM format.
            /// PKCS1 files begin with
            /// -----BEGIN RSA PRIVATE KEY-----
            pub fn new_pkcs1_pem(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let bytes = pem::parse(private_key)?;
                Ok(Self(signature::RsaKeyPair::from_der(&bytes.contents)?))
            }
        }

        impl $verify_name {
            /// Create a new instance of the signature scheme using the
            /// provided public key in RSAPublicKey (PKCS1) DER format..
            pub fn new_pkcs1_der(public_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(public_key.into()))
            }

            /// Create a new instance of the signature scheme using the
            /// provided public key in RSAPublicKey (PKCS1) PEM format.
            /// PKCS1 files begin with
            /// -----BEGIN RSA PUBLIC KEY-----
            pub fn new_pkcs1_pem(public_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let bytes = pem::parse(public_key)?;
                Ok(Self(bytes.contents.into()))
            }

            /// Create a new instance of the signature scheme using the
            /// provided public key in SPKI DER format.
            pub fn new_spki_der(spki: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let public_key = spki_to_unparsed_public_key(spki)?;
                Ok(Self(public_key.into()))
            }

            /// Create a new instance of the signature scheme using the
            /// provided public key in SPKI PEM format.
            pub fn new_spki_pem(spki_pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let spki = pem::parse(spki_pem)?;
                let public_key = spki_to_unparsed_public_key(&spki.contents)?;
                Ok(Self(public_key.into()))
            }
        }

        impl HttpSignatureSign for $sign_name {
            fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
                let mut tag = vec![0; self.0.public_modulus_len()];
                self.0
                    .sign(
                        &signature::$sign_alg,
                        &rand::SystemRandom::new(),
                        bytes_to_sign,
                        &mut tag,
                    )
                    .expect("Signing should be infallible");
                general_purpose::STANDARD.encode(&tag)
            }
            fn name(&self) -> &str {
                $name
            }
        }
        impl HttpSignatureVerify for $verify_name {
            fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool {
                let tag = match general_purpose::STANDARD.decode(signature) {
                    Ok(tag) => tag,
                    Err(_) => return false,
                };
                signature::VerificationAlgorithm::verify(
                    &signature::$verify_alg,
                    self.0.as_slice().into(),
                    bytes_to_verify.into(),
                    tag.as_slice().into(),
                )
                .is_ok()
            }
            fn name(&self) -> &str {
                $name
            }
        }
    };
}

// Use the spki crate from RustCrypto to  parse any SubjectPublicKeyInfo formatted
// file and return the actual public key bits.  This is much cleaner and safer
// than trying to manually grab bits from an unparsed blob.
//
// This provides support for actually reading standard formatted key files, such
// as those generated by Openssl.  This is necessary because ring-rs does not
// have any built in support for consuming public keys in any standard format. IF
// that ever materializes, this should be re-engineered to leveage that code
// directly.
fn spki_to_unparsed_public_key(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let spki = SubjectPublicKeyInfoRef::try_from(bytes)?;
    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

macro_rules! ecdsa_signature {
    ({$sign_name:ident($sign_alg:ident), $verify_name:ident($verify_alg:ident)} = $name:literal) => {
        #[doc = "Implementation of the signing half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $sign_name(signature::EcdsaKeyPair);

        #[doc = "Implementation of the verification half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $verify_name(Vec<u8>);

        impl $sign_name {
            /// Create a new instance of the signature scheme using the
            /// provided private key in PKCS8 DER format.
            pub fn new_pkcs8(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(signature::EcdsaKeyPair::from_pkcs8(
                    &signature::$sign_alg,
                    private_key,
                )?))
            }

            /// Create a new instance of the signature scheme using the
            /// provided private key in PKCS8 PEM format.
            /// PKCS8 PEM files begin with
            /// -----BEGIN PRIVATE KEY-----
            pub fn new_pkcs8_pem(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let bytes = pem::parse(private_key)?;
                Ok(Self(signature::EcdsaKeyPair::from_pkcs8(
                    &signature::$sign_alg,
                    &bytes.contents,
                )?))
            }
        }

        impl $verify_name {
            /// Create a new instance of the signature scheme using the
            /// provided public key in SPKI DER format.
            pub fn new_spki_der(spki: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let public_key = spki_to_unparsed_public_key(spki)?;
                Ok(Self(public_key.into()))
            }
            /// Create a new instance of the signature scheme using the
            /// provided public key in SPKI PEM format.
            pub fn new_spki_pem(spki_pem: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                let spki = pem::parse(spki_pem)?;
                let public_key = spki_to_unparsed_public_key(&spki.contents)?;
                Ok(Self(public_key.into()))
            }
        }

        impl HttpSignatureSign for $sign_name {
            fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
                let tag = self
                    .0
                    .sign(&rand::SystemRandom::new(), bytes_to_sign)
                    .expect("Signing should be infallible");
                general_purpose::STANDARD.encode(&tag)
            }
            fn name(&self) -> &str {
                $name
            }
        }

        impl HttpSignatureVerify for $verify_name {
            fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool {
                let tag = match general_purpose::STANDARD.decode(signature) {
                    Ok(tag) => tag,
                    Err(_) => return false,
                };
                signature::VerificationAlgorithm::verify(
                    &signature::$verify_alg,
                    self.0.as_slice().into(),
                    bytes_to_verify.into(),
                    tag.as_slice().into(),
                )
                .is_ok()
            }
            fn name(&self) -> &str {
                $name
            }
        }
    };
}

rsa_signature!({RsaSha256Sign(RSA_PKCS1_SHA256), RsaSha256Verify(RSA_PKCS1_2048_8192_SHA256)} = "rsa-v1_5-sha256");
rsa_signature!({RsaSha512Sign(RSA_PKCS1_SHA512), RsaSha512Verify(RSA_PKCS1_2048_8192_SHA512)} = "rsa-v1_5-sha512");
rsa_signature!({RsaPssSha256Sign(RSA_PSS_SHA512), RsaPssSha256Verify(RSA_PSS_2048_8192_SHA512)} = "rsa-pss-sha512");
rsa_signature!({RsaPssSha512Sign(RSA_PSS_SHA512), RsaPssSha512Verify(RSA_PSS_2048_8192_SHA512)} = "rsa-pss-sha512");
ecdsa_signature!({EcdsaP256Sha256Sign(ECDSA_P256_SHA256_ASN1_SIGNING), EcdsaP256Sha256Verify(ECDSA_P256_SHA256_ASN1)} = "ecdsa-p256-sha256");
