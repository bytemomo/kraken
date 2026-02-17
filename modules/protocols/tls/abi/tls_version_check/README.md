# tls_version_check (ABI v1)

Summarizes which TLS protocol versions a server accepts by attempting handshakes for TLS 1.0–1.3 using OpenSSL.

## Parameters (optional)

- `min_version` / `max_version`: restrict checks to a range (`TLS1.0`, `TLS1.1`, `TLS1.2`, `TLS1.3`).
- `sni`: override SNI hostname (defaults to target host).

## Build

```bash
cd modules/protocols/tls/abi/tls_version_check
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Usage (campaign snippet)

```yaml
steps:
    - id: tls-version-check
      type: lib
      api: 0
      exec:
          abi:
              library_path: "./modules/protocols/tls/abi/tls_version_check/build/tls_version_check.so"
              symbol: "kraken_run"
      required_tags: ["supports:tls"]
      params:
          min_version: "TLS1.2"
          sni: "broker.example.com"
```

## Finding IDs

- `TLS-SUPPORT-OVERVIEW`: Summary of TLS version support for the target.

## Output

- Single finding with evidence keys `tls1.0`, `tls1.1`, `tls1.2`, `tls1.3` marked `supported`, `not_supported`, `not_available` (OpenSSL-lacking), or `skipped` (outside requested range). Severity is raised to `medium` if TLS 1.0/1.1 are accepted.
