# Kraken

Kraken is a security assessment suite for ICS/IoT environments, built around three core principles:

1. **Orchestration first** - Config parsing, discovery, scheduling, and reporting
2. **Safety by default** - Conservative defaults, bounded concurrency, timeouts
3. **Evidence as first-class output** - Structured findings, attack tree evaluation

## Components

| Component   | Description                                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Kraken**  | Server-side security testing orchestrator. Executes modules for fuzzing, CVE checks, misconfiguration detection, and protocol conformance testing. |
| **Trident** | Transport abstraction library introducing the `Conduit` concept for protocol-agnostic I/O.                                                         |

## Features

### Multi-Protocol Support

- **MQTT** - Authentication testing, ACL probing, conformance validation, CVE replay
- **RTSP** - Service discovery, path enumeration, credential testing
- **TLS** - Version detection, certificate inspection
- **EtherCAT** - Packet injection, man-in-the-middle, denial of service

### Module System

Kraken supports four module types:

- **Native (Go)** - Compiled directly into the binary
- **Lib (ABI v1/v2)** - C/Rust shared libraries loaded at runtime
- **Container** - OCI container modules (Docker/Podman) for fuzzing campaigns
- **gRPC** - Remote service modules for distributed testing

### Attack Tree Evaluation

YAML-based attack trees with:

- AND/OR/LEAF node logic
- Configurable finding modes (any/all/threshold)
- Automatic Mermaid graph generation
- Per-target and aggregated reporting

### Transport Abstraction

Trident provides composable protocol stacks through the `Conduit` interface:

```go
type Conduit[V any] interface {
    Dial(ctx context.Context) error
    Close() error
    Kind() Kind
    Stack() []string
    Underlying() V
}
```

Supported transports: TCP, TLS, UDP, DTLS, Raw IP, Ethernet

## Project Structure

```text
.
├── campaigns/                # Campaign definitions
│   ├── iot-standard.yaml     # Production campaign
│   ├── iot-black-fuzz.yaml   # Black-box fuzzing (Boofuzz)
│   ├── iot-grey-fuzz.yaml    # Grey-box fuzzing (AFL++)
│   └── trees/
│       └── iot.yaml          # Attack tree definitions
├── docs/
│   ├── kraken/               # Kraken architecture & usage docs
│   ├── trident/              # Trident design docs
│   ├── MODULE.md             # Module API documentation
│   ├── POLICY.md             # Security/execution policy
│   └── TESTING.md            # Testing guide
├── kraken/                   # Kraken orchestrator
│   ├── internal/
│   │   ├── adapter/          # Report writers (JSON, attack tree, YAML config)
│   │   ├── domain/           # Core types (Campaign, Finding, Module, AttackNode)
│   │   ├── loader/           # Dynamic library loader (Unix/Windows)
│   │   ├── modules/          # Native modules (mqtt, rtsp)
│   │   ├── native/           # Module registry
│   │   ├── protocol/         # Protocol utilities
│   │   ├── runner/           # Parallel execution engine
│   │   ├── scanner/          # nmap-based discovery + EtherCAT scanner
│   │   └── testutil/         # Test helpers (certs, MQTT, servers)
│   ├── pkg/
│   │   ├── moduleabi/        # ABI headers (v1, v2)
│   │   └── modulepb/        # gRPC protobuf definitions
│   └── main.go
├── modules/                  # External protocol modules
│   └── protocols/
│       ├── mqtt/             # MQTT ABI modules + fuzzing harnesses
│       ├── rtsp/             # RTSP ABI modules
│       ├── tls/              # TLS ABI modules (C + Rust)
│       └── ethercat/         # EtherCAT ABI modules
├── resources/                # Evaluation scenarios
│   ├── scenario-a/           # MQTT ICS (Smart Grid/SCADA)
│   ├── scenario-b/           # EtherCAT Fieldbus
│   └── scenario-c/           # RTSP Surveillance
├── trident/                  # Transport abstraction library
│   └── conduit/
├── deploy/                   # Deployment configs & utilities
└── dist/                     # Build outputs
```

## Quick Start

### Building

```sh
cd kraken
go build -o kraken .
```

Or using the Justfile:

```sh
just kraken-build       # Go binary only
just kraken-build-all   # Go binary + ABI modules
```

### Running a Campaign

```sh
./dist/kraken -campaign campaigns/iot-standard.yaml \
              -cidrs "192.168.1.0/24" \
              -out kraken-results
```

### Scenarios

Scenarios are self-contained evaluation environments that simulate real-world ICS/IoT deployments. Each one is a Docker/Podman-based setup representing a specific industrial protocol use case:

| Scenario       | Protocol | Domain              |
| -------------- | -------- | ------------------- |
| **scenario-a** | MQTT     | Smart Grid / SCADA  |
| **scenario-b** | EtherCAT | Industrial Fieldbus |
| **scenario-c** | RTSP     | Surveillance        |

Each scenario bundles a Dockerfile, campaign YAML, setup scripts, TLS certificates, seed captures, and security profiles. Security profiles (`insecure`, `partial`, `hardened`) control the target's hardening level — an `insecure` profile should produce many findings, while `hardened` should produce fewer, validating that security controls work.

```sh
just scenario_run a insecure   # MQTT broker with no hardening
just scenario_run a hardened   # MQTT broker, locked down
just scenario_b_run            # EtherCAT (Docker-based)
```

### Results

Results are written to `{out}/{campaign_id}/{timestamp}/`:

- `assessment.json` - All findings
- `assessment.success.json` - Successful findings only
- `runs/{host}_{port}.json` - Per-target results
- `attack-trees/summary.md` - Attack tree evaluation summary
- `attack-trees/{host}_{port}.md` - Per-target attack tree details with Mermaid graphs

## Fuzzing

```sh
just fuzz-setup              # Configure host for AFL++
just fuzz-build mqtt:connect # Build fuzzing container
just fuzz-run mqtt:connect   # Run fuzzer
```

## Documentation

- [Kraken docs](docs/kraken/documentation.md) - Campaign orchestration, module APIs, attack trees
- [Trident docs](docs/trident/documentation.md) - Transport abstraction and conduit system
- [Module API](docs/MODULE.md) - Module development guide
- [Policy](docs/POLICY.md) - Execution policies and safety controls

## Testing

```sh
go test ./trident/...
go test ./kraken/...

# Or via Justfile
just test
```
