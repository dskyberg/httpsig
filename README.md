# http-sig

This crate started as a fork of [PassFort/http-signatures](https://github.com/PassFort/http-signatures) that has been
updated to implement the latest draft of [HTTP Message Signatures](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-17.html).

## To Do
This version is a partial impementation of HTTP Message Signatures.  The following
is not supported:
- Response signing
- Processing `Accept-Signature`
- `@request-response` specialty component


## Features

This crate is intended to be used with multiple different HTTP clients and/or servers.
As such, client/server-specific implementations are gated by correspondingly named
features.

### Supported crates:

| Crate / Feature name                                     | Client/Server | Notes                                                    |
| -------------------------------------------------------- | ------------- | -------------------------------------------------------- |
| [reqwest](https://docs.rs/reqwest/0.11.10/reqwest/)      | Client        | Supports blocking and non-blocking requests.<sup>1</sup> |
| [actix-web](https://docs.rs/actix-web/latest/actix_web/) | Server        |                                                          |  |

1. Due to limitations of the reqwest API, payload digests cannot be calculated automatically for non-blocking, streaming requests. For
   these requests, the user must add the digest header manually before signing the request, or else the `Digest` header will
   not be included in the signature. Automatic digests for streaming requests *are* supported via the blocking API.

### Supported signature algorithms

The following algorithms are listed in the [Algorithm registry](https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-17.html#name-http-signature-algorithms-4):

* `hmac-sha256`
* `rsa-pss-sha512`
* `rsa-v1_5-sha256`
* `ecdsa-p256-sha256`

### Supported digest algorithms
The following digest algorithmes are supported:

* `SHA-256`
* `SHA-512`

## Interoperability

The current interop target is [HTTP Message Signatures](httpsig.org).  However, the
default RSA key format presented by httpsig.org is not compatible with the Rust
implementation of [openssl](docs.rs/openssl) or with [Ring](docs.rs/ring).  I recommend using my [Key Tool](https://github.com/dskyberg/kt) to format the httpsig.org private keys to standard RSA PKCS8
key format.

The [http-sig-validator](./httpsig-validator) sub crate provides a CLI for testing canonicalization,
signing, and verifying.

Download an RSA private key PEM file from httpsig.org  run:

````shell,ignore
> kt convert -i [downloaded pem file] -a RSA -o [converted pem file]
````
## Example usage (reqwest)

````rust,ignore
use http_sig::*;

const SECRET_KEY: &[u8] = b"secret";
let label = "sig";
let key_id = "My Key";
let config = SigningConfig::new_default(&label, &key_id, SECRET_KEY);

let client = reqwest::blocking::Client::new();

let req = client
   .get("http://localhost:8080/")
   .build()
   .unwrap()
   .signed(&config)
   .unwrap();

let result = client.execute(req).unwrap();
````
## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](http://apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))


# Contributing

Open an issue or send a PR. All contributions intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[SEMANTICS]:  https://tools.ietf.org/id/draft-ietf-httpbis-semantics-17.html
[HTTPBIS]: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-17.html
[httpsig.org]: https://httpsig.org
