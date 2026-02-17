# Kraken Module System

This document describes Kraken's module system, including module types, APIs, adapters, and how to create new modules.

---

## Overview

Kraken's module system is designed to separate **orchestration** (scheduling, safety, reporting) from **protocol logic** (actual security checks). Modules implement the protocol-specific work while Kraken handles:

- Target discovery and classification
- Connection management (dial, retry, timeout)
- Safety policy enforcement
- Result aggregation and reporting

---

## Module Types

Kraken supports five module types, each with a different execution model:

| Type     | Description                           | Adapter                | Use Case                            |
| -------- | ------------------------------------- | ---------------------- | ----------------------------------- |
| `native` | Go functions compiled into Kraken     | `NativeBuiltinAdapter` | Built-in protocol modules           |
| `lib`    | Shared libraries (C/C++/Rust) via FFI | `ABIModuleAdapter`     | Performance-critical or legacy code |
| `grpc`   | Remote services via gRPC              | `GRPCModuleAdapter`    | Distributed or isolated execution   |
| `cli`    | External executables                  | `CLIModuleAdapter`     | Wrapping existing tools             |
| `fuzz`   | Fuzzing harnesses                     | `DockerModuleAdapter`  | Containerized fuzz campaigns        |

---

## Module Definition (YAML)

### Location: `kraken/internal/domain/module.go`

```go
type Module struct {
    ModuleID     string        `yaml:"id"`
    RequiredTags []string      `yaml:"required_tags,omitempty"`
    MaxDuration  time.Duration `yaml:"max_duration,omitempty"`
    Type         ModuleType    `yaml:"type"` // native|lib|grpc|cli|fuzz
    Aggressive   bool          `yaml:"aggressive,omitempty"`

    ExecConfig struct {
        ABI    *ABIConfig    `yaml:"abi,omitempty"`
        GRPC   *GRPCConfig   `yaml:"grpc,omitempty"`
        CLI    *CLIConfig    `yaml:"cli,omitempty"`
        Docker *DockerConfig `yaml:"docker,omitempty"`

        Conduit          *ConduitConfig `yaml:"conduit,omitempty"`
        ConduitTemplates []string       `yaml:"conduit_templates,omitempty"`
        Params           map[string]any `yaml:"params,omitempty"`
    } `yaml:"exec"`
}
```

### Key Fields

| Field           | Required         | Description                                            |
| --------------- | ---------------- | ------------------------------------------------------ |
| `id`            | Yes              | Unique module identifier                               |
| `type`          | Yes              | Execution type: `native`, `lib`, `grpc`, `cli`, `fuzz` |
| `required_tags` | No               | Target must have all these tags to run module          |
| `max_duration`  | Policy-dependent | Maximum execution time (required by default)           |
| `aggressive`    | No               | Mark as potentially disruptive (blocked by default)    |
| `exec.params`   | No               | Module-specific parameters                             |

---

## Native Modules (Go)

Native modules are Go functions compiled directly into Kraken. They have full access to Go's ecosystem and Kraken's internal types.

### Registry

**Location: `kraken/internal/native/registry.go`**

```go
// ModuleFunc is the signature implemented by builtin Go modules.
type ModuleFunc func(
    ctx context.Context,
    mod *domain.Module,
    target domain.Target,
    res Resources,
    params map[string]any,
    timeout time.Duration,
) (domain.RunResult, error)

// Descriptor defines how a native module should be run.
type Descriptor struct {
    Run         ModuleFunc
    Kind        cnd.Kind          // KindStream, KindDatagram, KindFrame
    Stack       []domain.LayerHint
    Description string
}

// Register stores the module implementation under the provided ID.
func Register(id string, desc Descriptor)

// Lookup returns the registered module descriptor.
func Lookup(id string) (Descriptor, bool)
```

### Resources

The `Resources` struct provides conduit factories for establishing connections:

```go
type Resources struct {
    StreamFactory   func(ctx context.Context) (interface{}, func(), error)
    DatagramFactory func(ctx context.Context) (interface{}, func(), error)
    FrameFactory    func(ctx context.Context) (interface{}, func(), error)
}
```

### Example: MQTT Dictionary Attack

**Location: `kraken/internal/modules/mqtt/dictionary.go`**

```go
func registerDictionaryAttack() {
    native.Register("mqtt-dict-attack", native.Descriptor{
        Run:  runMQTTDictionaryAttack,
        Kind: cnd.KindStream,
        Stack: []domain.LayerHint{
            {Name: "tcp"},
        },
        Description: `Attempts MQTT CONNECT handshakes with a credential dictionary.`,
    })
}

func runMQTTDictionaryAttack(
    ctx context.Context,
    mod *domain.Module,
    target domain.Target,
    res native.Resources,
    params map[string]any,
    timeout time.Duration,
) (domain.RunResult, error) {
    result := domain.RunResult{Target: target}

    // Get a stream connection
    handle, cleanup, err := res.StreamFactory(ctx)
    if err != nil {
        return result, err
    }
    defer cleanup()

    stream := handle.(cnd.Stream)

    // Perform MQTT operations...
    // Add findings to result...

    return result, nil
}
```

### Campaign YAML for Native Module

```yaml
tasks:
    - id: mqtt-dict-attack
      type: native
      required_tags: ["protocol:mqtt"]
      max_duration: 60s
      exec:
          params:
              credentials_file: "./wordlists/mqtt.txt"
```

---

## ABI Modules (C/C++/Rust Shared Libraries)

ABI modules are shared libraries loaded via FFI. Kraken supports two API versions:

### API Versions

| Version | Entry Point       | Connection Model                   | Use Case                |
| ------- | ----------------- | ---------------------------------- | ----------------------- |
| **V1**  | `kraken_run()`    | Module manages its own connections | Full connection control |
| **V2**  | `kraken_run_v2()` | Runner provides connected conduit  | Protocol-focused logic  |

### V1 API

**Header: `kraken/pkg/moduleabi/kraken_module_abi.h`**

```c
#define KRAKEN_ABI_VERSION 1u

typedef struct {
    const char *host;
    uint16_t port;
} KrakenHostPort;

typedef struct {
    const char *id;
    const char *module_id;
    bool success;
    const char *title;
    const char *severity;
    const char *description;
    KrakenEvidence evidence;
    KrakenStringList tags;
    int64_t timestamp;
    KrakenHostPort target;
} KrakenFinding;

typedef struct {
    KrakenHostPort target;
    KrakenFinding *findings;
    size_t findings_count;
    KrakenStringList logs;
} KrakenRunResult;

/* Main entrypoint */
int kraken_run(
    const char *host,
    uint32_t port,
    uint32_t timeout_ms,
    const char *params_json,
    KrakenRunResult **out_result
);

void kraken_free(void *p);
```

### V2 API

**Header: `kraken/pkg/moduleabi/kraken_module_abi_v2.h`**

```c
#define KRAKEN_ABI_VERSION_V2 2u

typedef void *KrakenConnectionHandle;

typedef enum {
    KRAKEN_CONN_TYPE_STREAM = 1,
    KRAKEN_CONN_TYPE_DATAGRAM = 2,
    KRAKEN_CONN_TYPE_FRAME = 3,
} KrakenConnectionType;

typedef enum {
    KRAKEN_TARGET_KIND_NETWORK = 1,
    KRAKEN_TARGET_KIND_ETHERCAT = 2,
} KrakenTargetKind;

typedef struct {
    const char *iface;
    uint16_t position;
    uint16_t station_addr;
    uint32_t vendor_id;
    uint32_t product_code;
    // ... other EtherCAT fields
} KrakenEtherCATTarget;

typedef struct {
    KrakenTargetKind kind;
    union {
        KrakenHostPort network;
        KrakenEtherCATTarget ethercat;
    } u;
} KrakenTarget;

/* I/O Operations provided by Runner */
typedef struct {
    int64_t (*send)(KrakenConnectionHandle conn, const uint8_t *data, size_t len, uint32_t timeout_ms);
    int64_t (*recv)(KrakenConnectionHandle conn, uint8_t *buffer, size_t buffer_size, uint32_t timeout_ms);
    const KrakenConnectionInfo *(*get_info)(KrakenConnectionHandle conn);
    KrakenConnectionHandle (*open)(KrakenConnectionHandle conn, uint32_t timeout_ms);  /* optional */
    void (*close)(KrakenConnectionHandle conn);  /* optional */
} KrakenConnectionOps;

/* Main entrypoint */
int kraken_run_v2(
    KrakenConnectionHandle conn,
    const KrakenConnectionOps *ops,
    const KrakenTarget *target,
    uint32_t timeout_ms,
    const char *params_json,
    KrakenRunResultV2 **out_result
);

void kraken_free_v2(void *p);
```

### V2 Module Template (C)

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
    // 1. Allocate result
    KrakenRunResultV2 *result = calloc(1, sizeof(KrakenRunResultV2));
    copy_target(&result->target, target);

    // 2. Use conduit I/O
    const char *probe = "HELLO\n";
    int64_t sent = ops->send(conn, (const uint8_t*)probe, strlen(probe), timeout_ms);

    uint8_t buffer[4096];
    int64_t received = ops->recv(conn, buffer, sizeof(buffer), timeout_ms);

    // 3. Create findings
    KrakenFindingV2 finding = {0};
    finding.id = mystrdup("MY-FINDING-ID");
    finding.module_id = mystrdup("my-module");
    finding.success = true;
    finding.title = mystrdup("Example Finding");
    finding.severity = mystrdup("info");
    finding.description = mystrdup("This is an example finding");
    copy_target(&finding.target, target);
    add_finding_v2(result, &finding);

    // 4. Return result
    *out_result = result;
    return 0;
}

KRAKEN_API void kraken_free_v2(void *p) {
    // Free allocated memory
}
```

### Campaign YAML for ABI Module

**V1 Module:**

```yaml
tasks:
    - id: tls-version-check
      type: lib
      required_tags: ["supports:tls"]
      max_duration: 30s
      exec:
          abi:
              api: v1
              library_path: "./modules/protocols/tls/abi/tls_version_check/build/tls_version_check"
              symbol: "kraken_run"
```

**V2 Module with Conduit:**

```yaml
tasks:
    - id: mqtt-auth-check
      type: lib
      required_tags: ["protocol:mqtt"]
      max_duration: 30s
      exec:
          abi:
              api: v2
              library_path: "./modules/protocols/mqtt/abi/mqtt_auth_check/build/mqtt_auth_check"
              symbol: "kraken_run_v2"
          conduit:
              kind: stream
              stack:
                  - name: tcp
                  - name: tls
                    params:
                        skip_verify: true
          params:
              creds_file: "./wordlists/mqtt.txt"
```

**V2 Module for EtherCAT:**

```yaml
tasks:
    - id: ethercat-slave-info
      type: lib
      required_tags: ["protocol:ethercat"]
      max_duration: 30s
      exec:
          abi:
              api: v2
              library_path: "./modules/protocols/ethercat/abi/ethercat_slave_info/build/ethercat_slave_info"
              symbol: "kraken_run_v2"
          conduit:
              kind: frame # Layer 2 raw Ethernet
```

---

## Conduit System

Conduits abstract transport layers, allowing modules to focus on protocol logic.

### Conduit Kinds

| Kind           | Value | Transport    | Use Case             |
| -------------- | ----- | ------------ | -------------------- |
| `KindStream`   | 1     | TCP, TLS     | MQTT, RTSP, HTTP     |
| `KindDatagram` | 2     | UDP, DTLS    | CoAP, DNS            |
| `KindFrame`    | 3     | Raw Ethernet | EtherCAT, Modbus TCP |

### Layer Stacks

Conduits are built by stacking transport layers:

```yaml
conduit:
    kind: stream
    stack:
        - name: tcp
        - name: tls
          params:
              skip_verify: true
              min_version: "1.2"
```

**Available Layers:**

| Layer  | Kind     | Description             |
| ------ | -------- | ----------------------- |
| `tcp`  | Stream   | Raw TCP connection      |
| `tls`  | Stream   | TLS over TCP            |
| `udp`  | Datagram | Raw UDP                 |
| `dtls` | Datagram | DTLS over UDP           |
| `eth`  | Frame    | Raw Ethernet (EtherCAT) |

### Conduit Templates

Templates allow a single task to expand into multiple transport variants:

```yaml
conduit_templates:
    - name: tcp
      kind: stream
      stack:
          - name: tcp
    - name: tls
      kind: stream
      stack:
          - name: tcp
          - name: tls
            params:
                skip_verify: true
      required_tags: ["supports:tls"]

tasks:
    - id: mqtt-check
      type: native
      required_tags: ["protocol:mqtt"]
      max_duration: 30s
      exec:
          conduit_templates: [tcp, tls] # Expands to mqtt-check-tcp, mqtt-check-tls
```

---

## Adapters

Adapters translate between Kraken's runner and specific module execution models.

### NativeBuiltinAdapter

**Location: `kraken/internal/runner/adapter/native.go`**

- Executes Go functions from the native registry
- Builds conduit factories based on target type
- Strips template suffixes (e.g., `-tcp`, `-tls`) when looking up modules

```go
func (n *NativeBuiltinAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
    desc, ok := native.Lookup(m.ModuleID)
    if !ok {
        // Try stripping conduit template suffix
        baseID := stripTemplateSuffix(m.ModuleID)
        desc, ok = native.Lookup(baseID)
    }

    resources, err := n.buildResources(ctx, t, desc.Kind, desc.Stack)
    if err != nil {
        return domain.RunResult{Target: t}, err
    }

    return desc.Run(ctx, m, t, resources, params, timeout)
}
```

### ABIModuleAdapter

**Location: `kraken/internal/runner/adapter/abi.go`**

- Loads shared libraries via `dlopen`/`dlsym`
- For V2: establishes conduit before calling module
- Provides `KrakenConnectionOps` callbacks for I/O

```go
func (a *ABIModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
    // For V2 modules, build conduit factory
    if m.ExecConfig.ABI.Version == domain.ModuleV2 && m.ExecConfig.Conduit != nil {
        factory = a.buildNetworkConduitFactory(addr, cfg.Kind, cfg.Stack, dialOpts)
        conduit, closeConduit, stackLayers, err = factory(timeout)
        // ...
    }

    module, err := loader.Load(abiConfig.LibraryPath)
    return module.Run(abiCtx, mergedParams, t, timeout, conduit)
}
```

### Conduit I/O Callbacks (V2)

**Location: `kraken/internal/loader/loader.go`**

The loader provides Go implementations for the C callbacks:

```go
//export go_conduit_send
func go_conduit_send(conn C.KrakenConnectionHandle, data *C.uint8_t, length C.size_t, timeout_ms C.uint32_t) C.int64_t {
    handle := v2HandleMap[uintptr(conn)]
    switch c := handle.conduit.(type) {
    case cnd.Stream:
        n, _, err := c.Send(ctx, goData, nil, &cnd.SendOptions{})
        return C.int64_t(n)
    case cnd.Datagram:
        // Similar for datagrams
    }
}

//export go_conduit_recv
func go_conduit_recv(conn C.KrakenConnectionHandle, buffer *C.uint8_t, buffer_size C.size_t, timeout_ms C.uint32_t) C.int64_t {
    // Read from conduit into buffer
}

//export go_conduit_open
func go_conduit_open(conn C.KrakenConnectionHandle, timeout_ms C.uint32_t) C.KrakenConnectionHandle {
    // Open a new connection using the same factory
}

//export go_conduit_close
func go_conduit_close(conn C.KrakenConnectionHandle) {
    // Close connection and free resources
}
```

---

## Target Types

### Network Target (HostPort)

```go
type HostPort struct {
    Host string
    Port uint16
}
```

### EtherCAT Target

```go
type EtherCATSlave struct {
    Interface   string  // Network interface (e.g., "eth0")
    Position    uint16  // Auto-increment position
    StationAddr uint16  // Configured station address
    AliasAddr   uint16  // Alias from EEPROM
    VendorID    uint32
    ProductCode uint32
    RevisionNo  uint32
    SerialNo    uint32
    PortStatus  uint16
}
```

---

## Finding Structure

Modules emit findings that are aggregated into reports:

```go
type Finding struct {
    ID          string         `json:"id"`           // Unique finding ID (e.g., "MQTT-ANON")
    ModuleID    string         `json:"module_id"`    // Module that generated it
    Success     bool           `json:"success"`      // Whether condition was demonstrated
    Title       string         `json:"title"`        // Human-readable title
    Severity    string         `json:"severity"`     // info, low, medium, high, critical
    Description string         `json:"description"`  // Detailed description
    Evidence    map[string]any `json:"evidence"`     // Supporting data
    Tags        []Tag          `json:"tags"`         // Categorization tags
    Timestamp   time.Time      `json:"timestamp"`
    Target      Target         `json:"target"`       // What was tested
}
```

### Finding IDs

Finding IDs should be consistent and can be referenced in attack trees:

| Pattern          | Example                              | Description               |
| ---------------- | ------------------------------------ | ------------------------- |
| `PROTOCOL-ISSUE` | `MQTT-ANON`                          | Protocol-specific finding |
| `CVE-YYYY-NNNN`  | `CVE-2024-8376`                      | Known vulnerability       |
| `CERT-*`         | `CERT-EXPIRED`                       | Certificate issues        |
| `module-id-*`    | `mqtt-conformance-test-mqtt-3.1.4-5` | Test case specific        |

---

## Module Inventory

### ABI Modules

| Module                | API | Language | Description                 |
| --------------------- | --- | -------- | --------------------------- |
| `tls_version_check`   | V1  | C        | TLS version detection       |
| `cert_inspect`        | V1  | Rust     | Certificate posture checks  |
| `mqtt_auth_check`     | V2  | C        | MQTT authentication testing |
| `mqtt_acl_probe`      | V2  | C        | MQTT ACL probe              |
| `mqtt_sys_disclosure` | V1  | C        | $SYS topic leakage          |
| `mqtt_replay`         | V1  | C        | MQTT packet replay          |

### Native Modules (Go)

| Module                  | Conduit | Description                    |
| ----------------------- | ------- | ------------------------------ |
| `mqtt-dict-attack`      | Stream  | Credential dictionary attack   |
| `mqtt-conformance-test` | Stream  | Protocol conformance testing   |
| `rtsp-surface-scan`     | Stream  | RTSP discovery and enumeration |
| `rtsp-dict-attack`      | Stream  | RTSP credential testing        |

---

## Creating New Modules

### Native Module Checklist

1. Create file in `kraken/internal/modules/<protocol>/`
2. Implement `ModuleFunc` signature
3. Register with `native.Register()` in an `init()` or `Init()` function
4. Specify `Kind` and `Stack` in descriptor
5. Use `Resources` factories for connections
6. Return findings in `RunResult`

### ABI Module Checklist

1. Create directory in `modules/protocols/<protocol>/abi/<module_name>/`
2. Include appropriate header (`kraken_module_abi.h` or `kraken_module_abi_v2.h`)
3. Implement `kraken_run()` (V1) or `kraken_run_v2()` (V2)
4. Implement `kraken_free()` / `kraken_free_v2()`
5. Export `KRAKEN_MODULE_ABI_VERSION` or `KRAKEN_MODULE_ABI_VERSION_V2`
6. Create `CMakeLists.txt` for building
7. Add task definition in campaign YAML

### V1 vs V2 Decision

| Choose V1 when...                 | Choose V2 when...             |
| --------------------------------- | ----------------------------- |
| Need full connection control      | Protocol logic only           |
| Custom connection pooling         | Standard TCP/TLS/UDP/DTLS     |
| Multiple simultaneous connections | Sequential request/response   |
| Non-standard transports           | EtherCAT Frame support needed |

---

## Related Files

| File                                          | Purpose                          |
| --------------------------------------------- | -------------------------------- |
| `kraken/internal/domain/module.go`            | Module struct definition         |
| `kraken/internal/native/registry.go`          | Native module registry           |
| `kraken/internal/loader/loader.go`            | ABI module loader                |
| `kraken/internal/runner/adapter/native.go`    | Native adapter                   |
| `kraken/internal/runner/adapter/abi.go`       | ABI adapter                      |
| `kraken/pkg/moduleabi/kraken_module_abi.h`    | V1 ABI header                    |
| `kraken/pkg/moduleabi/kraken_module_abi_v2.h` | V2 ABI header                    |
| `modules/protocols/README.md`                    | Module inventory and finding IDs |
| `modules/protocols/`                   | Protocol-specific modules        |
