# cert_inspect (ABI v1, Rust)

Inspects the server certificate over TLS and reports common posture issues (expiry, weak keys, SHA1, self-signed, SAN/hostname mismatches).

## Build

```bash
cd modules/protocols/tls/abi/cert_inspect
cargo build --release
# shared library lands in target/release/
```

## Parameters (optional)

- `tls_insecure` (bool, default true): skip certificate verification when fetching the chain.
- `warn_days` (int, default 21): warn when expiry is within this window.
- `min_rsa_bits` (int, default 2048): minimum RSA key size.
- `allow_sha1` (bool, default false): whether SHA1 signatures are permitted.
- `disallow_self_signed` (bool, default true)
- `match_hostname` (bool, default true)
- `require_san` (bool, default true)
- `require_server_auth` (bool, default false): require Extended Key Usage serverAuth.

## Usage (campaign snippet)

```yaml
steps:
    - id: cert-inspect
      type: lib
      api: 0
      required_tags: ["supports:tls"]
      exec:
          abi:
              library_path: "./modules/protocols/tls/abi/cert_inspect/target/release/libcert_inspect.so"
              symbol: "kraken_run"
      params:
          warn_days: 14
          min_rsa_bits: 3072
          disallow_self_signed: true
```

## Finding IDs

- `CERT-EXPIRED`: Certificate has expired.
- `CERT-EXPIRING`: Certificate expires within the configured warning window.
- `CERT-SELFSIGNED`: Certificate is self-signed.
- `CERT-SHA1`: Certificate uses deprecated SHA1 signature algorithm.
- `CERT-WEAKKEY`: RSA key size is below the configured minimum.
- `CERT-HOSTNAME`: Certificate CN/SAN does not match the target hostname.
- `CERT-NOSAN`: Certificate lacks Subject Alternative Name extension.
- `CERT-NO-SERVER-AUTH`: Certificate lacks serverAuth Extended Key Usage (when `require_server_auth` is enabled).

## Output

- Findings note each violation (soon-to-expire, weak key, SHA1, self-signed, hostname/SAN issues) with evidence describing the failing check.
