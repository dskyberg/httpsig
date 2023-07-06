# HTTP Signature Validator
A test app to enable validating canonicalization assumptions.

## Canonicalization
To see the fully canonicalized signing input, that is subsequently digested
by either the signing or verification process.

Basic syntax:

```bash, no_run
> cat ../test_data/basic_request.txt | cargo run -- canonicalize \
  -l sig \
  -a "rsa-v1_5-sha256" \
  -k "test-key-rsa" \
  -d "host date content-digest"
```

This will produce the following output:

```http, no_run
"host": example.com
"date": Tue, 20 Apr 2021 02:07:55 GMT
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@signature-params": ("host" "date" "content-digest");keyid="test-key-rsa";alg="rsa-v1_5-sha256"
```

## Signing
Generate a signed request that can be tested with a verifying server.

```bash, no_run
> cat ../test_data/basic_request.txt | cargo run -q -- sign \
  -l sig \
  -d "host date digest" \
  -a "rsa-v1_5-sha256" \
  -k "test-key-rsa" \
  -p ../test_data/rsa-private.pem
```

The above will produce the following output:

```http, no_run
POST /foo?param=value&pet=dog HTTP/1.1
signature: sig=:Gv5M2DlTCg1cc7l1D4Vuu5Dx3DJ2+OCgv76dnmSDKzY=:
host: example.com
content-type: application/json
signature-input: sig=("host" "date" "digest");alg="hmac-sha256";keyid="test-key-rsa"
date: Sun, 05 Jan 2014 21:31:40 GMT
digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
content-length: 18

{"hello": "world"}
```

## Verification

Verify the signature on a signed request

```bash, no_run
> cat ../test_data/signed_request.txt | cargo run -q -- verify \
  -a "rsa-v1_5-sha256" \
  -k "test-key-rsa" \
  -u ../test_data/rsa-public.pem
```

If successful, **_there will be no output_**.  If verification fails, you can turn
on logging to see what might be failing:

```bash, no_run
cat ../test_data/signed_request.txt | RUST_LOG=httpsig=trace,httpsig_validator=trace \
cargo run -q -- verify \
  -a "rsa-v1_5-sha256" \
  -k "test-key-rsa" \
  -u ../test_data/rsa-public.pem
```

## All together now!

To test end-to-end, you can do something like the following:

```bash, no_run
> cat ../test_data/basic_request.txt | cargo run -q -- sign \
  -l sig \
  -d "host date digest" \
  -a "rsa-v1_5-sha256" \
  -k "test-key-rsa" \
  -p ../test_data/rsa-private.pem | cargo run -q -- verify \
  -a "rsa-v1_5-sha256" \
  -k "test-key-rsa" \
  -u ../test_data/rsa-public.pem
```
Again, if successful, there will be no output.

## Generating test keys

To generate an RSA private key usable by the Ring crate, use the following
Openssl CLI command:

```bash, no_run
> openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 | openssl pkcs8 -topk8 -nocrypt -outform der -out rsa-private.pem
```

## Interoperability with [httpsig.org]

### Public/Private keys
[httpsig.org] uses PKCS8 PEM encoded private keys, but with the `rsassaPss` AlgId, rather than with the `rsaEncryption   AlgId.  So, Ring hates it.

I am still working through openssl / Ring functional interoperability.  Any assistance anyone can provide would be much appreciated.

Using my KT app, you can fix the AlgId to work with Ring:

```bash, ignore
> kt convert -i <downloaded private.pem file> -a RSA -f PKCS8
```

[httpsig.org]: https://httpsig.org