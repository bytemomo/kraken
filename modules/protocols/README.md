# Protocol Modules

## Directory Structure

```
modules/protocols/
├── mqtt/
│   ├── abi/                  # ABI modules for MQTT
│   │   ├── mqtt_auth_check/  # MQTT authentication testing (v2)
│   │   ├── mqtt_acl_probe/   # MQTT ACL probe (v2)
│   │   ├── mqtt_sys_disclosure/  # $SYS topic leakage (v1)
│   │   └── mqtt_replay/      # MQTT packet replay (v1)
│   ├── container/            # Container modules for MQTT
│   │   └── boofuzz/          # Boofuzz fuzzer
│   ├── fuzz/                 # Fuzz harnesses by target
│   │   ├── mosquitto/
│   │   ├── nanomq/
│   │   └── wolfmqtt/
│   └── corpus/               # Shared seeds/dicts for MQTT
├── tls/
│   ├── abi/
│   │   ├── tls_version_check/    # TLS version detection (v1)
│   │   └── cert_inspect/         # Certificate inspection (Rust, v1)
│   └── corpus/
├── ethercat/
│   └── abi/
│       ├── ecat_dos.c
│       ├── ecat_inject.c
│       └── ecat_mitm.c
└── README.md
```

## Module API Versions

### V1 API (api: v1)

- Module receives `host` and `port` parameters
- Module creates its own connections
- Module handles all transport layer logic (TCP, TLS, etc.)
- Entry point: `kraken_run(host, port, timeout, params, result)`
- Use case: Modules that need full connection control (e.g., credential brute-forcing)

### V2 API (api: v2)

- Module receives a **connected conduit handle** and a **target** (network or EtherCAT)
- Runner establishes connection based on `conduit` configuration
- Module focuses on protocol logic only
- Entry point: `kraken_run_v2(conn, ops, target, timeout, params, result)`
- Callbacks: `ops->send()`, `ops->recv()`, `ops->get_info()`, `ops->open()`, `ops->close()`
- Conduit kinds: `stream` (TCP/TLS), `datagram` (UDP/DTLS), `frame` (Layer 2/EtherCAT)
- Target types: `KRAKEN_TARGET_KIND_NETWORK` or `KRAKEN_TARGET_KIND_ETHERCAT`
- Use case: Protocol-focused modules with conduit-based I/O

## Building Modules

### Prerequisites

- CMake 3.20+
- Ninja (or other build system)
- OpenSSL (for TLS modules)
- Rust toolchain (for Rust modules)

### Build All Modules

```bash
# Build all C/C++ modules
find modules/protocols -name CMakeLists.txt | while read cmakefile; do
  dir=$(dirname "$cmakefile")
  cmake -S "$dir" -B "$dir/build" -G Ninja -DCMAKE_BUILD_TYPE=Release
  cmake --build "$dir/build" --config Release
done

# Build Rust modules
cd modules/protocols/tls/abi/cert_inspect
cargo build --release
```

### Build Individual Module

```bash
cd modules/protocols/tls/abi/tls_version_check
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Module Status

| Module              | Type          | Language | Description                                       |
| ------------------- | ------------- | -------- | ------------------------------------------------- |
| tls_version_check   | ABI v1        | C        | Summarizes accepted TLS protocol versions         |
| mqtt_auth_check     | ABI v2        | C        | Tests anonymous MQTT auth and pub/sub on conduit  |
| mqtt_acl_probe      | ABI v2        | C        | Tests MQTT ACLs (connect/sub/pub per credential)  |
| cert_inspect        | ABI v1 (Rust) | Rust     | Certificate posture checks (expiry, key, SAN)     |
| mqtt_sys_disclosure | ABI v1        | C        | Detects `$SYS` topic leakage via `#` subscription |
| mqtt_replay         | ABI v1        | C        | Replays MQTT packet sequences (e.g., CVE repros)  |

## Finding IDs

Each module emits findings with unique IDs that can be referenced in attack trees.

### ABI Modules

| Finding ID             | Module              | Severity | Trigger Condition                                       |
| ---------------------- | ------------------- | -------- | ------------------------------------------------------- |
| `TLS-SUPPORT-OVERVIEW` | tls_version_check   | info/med | Always emitted; medium if TLS 1.0/1.1 accepted          |
| `MQTT-ANON`            | mqtt_auth_check     | high     | Broker accepts anonymous CONNECT                        |
| `MQTT-PUBSUB-ANON`     | mqtt_auth_check     | critical | Broker allows anonymous publish/subscribe               |
| `MQTT-WEAK-CREDS`      | mqtt_auth_check     | high     | Broker accepts credentials from wordlist                |
| `MQTT-ACL-SUB`         | mqtt_acl_probe      | high     | SUBSCRIBE to probe topic accepted                       |
| `MQTT-ACL-PUB`         | mqtt_acl_probe      | high     | PUBLISH to probe topic acknowledged (PUBACK)            |
| `mqtt-sys-disclosure`  | mqtt_sys_disclosure | high     | `$SYS` topics leaked via `#` wildcard subscription      |
| `CERT-EXPIRED`         | cert_inspect        | critical | Certificate has expired                                 |
| `CERT-EXPIRING`        | cert_inspect        | medium   | Certificate expires within warning window (default 21d) |
| `CERT-SELFSIGNED`      | cert_inspect        | medium   | Certificate is self-signed                              |
| `CERT-SHA1`            | cert_inspect        | medium   | Certificate uses deprecated SHA1 signature              |
| `CERT-WEAKKEY`         | cert_inspect        | high     | RSA key below minimum size (default 2048 bits)          |
| `CERT-HOSTNAME`        | cert_inspect        | high     | CN/SAN does not match target hostname                   |
| `CERT-NOSAN`           | cert_inspect        | medium   | Certificate lacks Subject Alternative Name extension    |
| `CERT-NO-SERVER-AUTH`  | cert_inspect        | medium   | Certificate lacks serverAuth EKU (if required)          |
| _(dynamic)_            | mqtt_replay         | varies   | Derived from loaded file name (e.g., `CVE-2024-8376`)   |

### Native Modules (Go)

| Finding ID            | Module          | Severity | Trigger Condition                          |
| --------------------- | --------------- | -------- | ------------------------------------------ |
| `MQTT-VALID-CREDS`    | mqtt-dictionary | high     | Broker accepts credentials from dictionary |
| `DEFAULT-CREDENTIALS` | mqtt-dictionary | high     | Broker accepts known default credentials   |

#### MQTT Conformance Test IDs

The `mqtt-conformance-test` module emits findings with IDs in the format `mqtt-conformance-test-{code}`:

| Finding ID                            | Trigger Condition                                |
| ------------------------------------- | ------------------------------------------------ |
| `mqtt-conformance-test-mqtt-3.1.4-5`  | Server acknowledges CONNECT with CONNACK         |
| `mqtt-conformance-test-mqtt-3.12.4-1` | Server responds to PINGREQ with PINGRESP         |
| `mqtt-conformance-test-mqtt-3.8.4-1`  | Server acknowledges SUBSCRIBE with SUBACK        |
| `mqtt-conformance-test-mqtt-3.3.4-1`  | Server acknowledges QoS 1 PUBLISH with PUBACK    |
| `mqtt-conformance-test-mqtt-3.10.4-4` | Server acknowledges UNSUBSCRIBE with UNSUBACK    |
| `mqtt-conformance-test-mqtt-3.1.2-22` | Server enforces Keep Alive timeout               |
| `mqtt-conformance-test-mqtt-4.8.2-2`  | Server accepts valid Shared Subscription         |
| `mqtt-conformance-test-mqtt-3.3.1-6`  | Server deletes retained message on zero-byte pub |
| `mqtt-conformance-test-mqtt-4.7.3-2`  | Server rejects invalid UTF-8 topic filter        |
| `mqtt-conformance-test-mqtt-3.1.0-2`  | Server disconnects client on second CONNECT      |

## Usage in Campaigns

### V1 Module Example

```yaml
tasks:
    - id: "tls-version-check"
      type: lib
      required_tags: ["supports:tls"]
      exec:
          abi:
              api: v1
              library_path: "./modules/protocols/tls/abi/tls_version_check/build/tls_version_check"
              symbol: "kraken_run"
```

### V2 Module Example (Network Target)

```yaml
tasks:
    - id: "mqtt-auth-check"
      type: lib
      required_tags: ["protocol:mqtt"]
      exec:
          abi:
              api: v2
              library_path: "./modules/protocols/mqtt/abi/mqtt_auth_check/build/mqtt_auth_check"
              symbol: "kraken_run_v2"
          conduit:
              kind: stream # or kind: 1
              stack:
                  - name: tcp
                  - name: tls
                    params:
                        skip_verify: true
          params:
              creds_file: "./wordlists/mqtt.txt"
```

### V2 Module Example (EtherCAT Target)

```yaml
tasks:
    - id: "ethercat-slave-info"
      type: lib
      required_tags: ["protocol:ethercat"]
      exec:
          abi:
              api: v2
              library_path: "./modules/protocols/ethercat/abi/build/ethercat_slave_info"
              symbol: "kraken_run_v2"
          conduit:
              kind: frame # Layer 2 raw Ethernet frames
```

## Creating New Modules

### V2 Module Template (Recommended)

```c
#define KRAKEN_MODULE_BUILD
#include <kraken_module_abi_v2.h>

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION_V2 = KRAKEN_ABI_VERSION_V2;

KRAKEN_API int kraken_run_v2(
    KrakenConnectionHandle conn,
    const KrakenConnectionOps *ops,
    const KrakenTarget *target,
    uint32_t timeout_ms,
    const char *params_json,
    KrakenRunResultV2 **out_result
) {
    // 1. Allocate result and copy target
    KrakenRunResultV2 *result = calloc(1, sizeof(KrakenRunResultV2));
    result->target.kind = target->kind;

    if (target->kind == KRAKEN_TARGET_KIND_NETWORK) {
        result->target.u.network.host = strdup(target->u.network.host);
        result->target.u.network.port = target->u.network.port;
    } else if (target->kind == KRAKEN_TARGET_KIND_ETHERCAT) {
        result->target.u.ethercat.iface = strdup(target->u.ethercat.iface);
        result->target.u.ethercat.position = target->u.ethercat.position;
        result->target.u.ethercat.station_addr = target->u.ethercat.station_addr;
        result->target.u.ethercat.vendor_id = target->u.ethercat.vendor_id;
        result->target.u.ethercat.product_code = target->u.ethercat.product_code;
        // ... copy other fields as needed
    }

    // 2. Use conduit I/O operations
    const char *probe = "HELLO\n";
    int64_t sent = ops->send(conn, (const uint8_t*)probe, strlen(probe), timeout_ms);

    uint8_t buffer[4096];
    int64_t received = ops->recv(conn, buffer, sizeof(buffer), timeout_ms);

    // 3. Create findings based on response (use KrakenFindingV2)
    // ... (see existing modules for examples)

    // 4. Return result
    *out_result = result;
    return 0;
}

KRAKEN_API void kraken_free_v2(void *p) {
    // Free allocated result memory
}
```
