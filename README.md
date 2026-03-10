# Kraken

**Security assessment suite for ICS/IoT environments.**

Kraken discovers, tests, and reports on industrial control systems and IoT devices across multiple protocols. It combines network scanning, modular security testing, protocol fuzzing, and attack tree evaluation into a single orchestrated workflow.

```
[ KRAKEN ]
┌─────────────────────────────────────────────────────────────┐
│  Campaign YAML ->  Discovery ->  Modules  -> Findings       │
│                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐   │
│  │  Targets │-->│ Scanners │-->│ Runners  │-->│ Reports │   │
│  │  CIDRs   │   │  nmap    │   │ native   │   │ JSON    │   │
│  │  Hosts   │   │ ethercat │   │ ABI/gRPC │   │ trees   │   │
│  └──────────┘   └──────────┘   │ container│   │ mermaid │   │
│                                └──────────┘   └─────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Protocols

| Protocol     | Capabilities                                                                     |
| ------------ | -------------------------------------------------------------------------------- |
| **MQTT**     | Authentication testing, ACL probing, conformance validation, CVE replay, fuzzing |
| **RTSP**     | Service discovery, path enumeration, credential testing                          |
| **TLS**      | Version detection, certificate inspection, cipher analysis                       |
| **EtherCAT** | Packet injection, man-in-the-middle, denial of service                           |

## How It Works

**1. Define a campaign** in YAML — targets, modules, attack trees, output settings.

**2. Run it.** Kraken scans the network, discovers services, and dispatches security modules against each target in parallel.

**3. Get results.** Structured findings, per-target reports, and attack tree evaluations with pass/fail verdicts.

## Module System

Kraken supports four module types, so you can write security checks in whatever makes sense:

| Type             | How it works                                                  |
| ---------------- | ------------------------------------------------------------- |
| **Native** (Go)  | Compiled into the binary. Fastest, simplest.                  |
| **Lib** (C/Rust) | Shared libraries loaded at runtime via ABI v1/v2.             |
| **Container**    | OCI images (Docker/Podman). Great for fuzzing harnesses.      |
| **gRPC**         | Remote services for distributed or language-agnostic modules. |

## Attack Trees

Define threat scenarios as YAML trees with AND/OR/LEAF logic. Kraken evaluates them against discovered findings and tells you which attack paths succeeded.

```
         ┌──────────────────────┐
         │    OR: Compromise    │
         │       MQTT Broker    │
         └──────────┬───────────┘
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │  LEAF   │ │   AND   │ │  LEAF   │
   │ No Auth │ │  Steal  │ │  CVE    │
   │ [pass]  │ │ Creds   │ │ Replay  │
   └─────────┘ └────┬────┘ └─────────┘
              ┌──────┴──────┐
              ▼             ▼
         ┌─────────┐  ┌─────────┐
         │  LEAF   │  │  LEAF   │
         │ Weak PW │  │ No TLS  │
         └─────────┘  └─────────┘
```

## TUI

Kraken ships with a terminal UI for interactive campaign management:

- **Tab 1 — Campaign**: Load YAML configs, set targets and interfaces
- **Tab 2 — Registry**: Browse and download community modules
- **Tab 3 — Execution**: Live progress, logs, and module status
- **Tab 4 — Results**: Finding details with severity and evidence
- **Tab 5 — Attack Tree**: Full 2D visualization with pass/fail indicators

Toggle between dark and light themes with `F1`.

## Quick Start

### Build

```sh
just kraken-build          # Binary only
just kraken-build-all      # Binary + ABI modules
```

Or manually:

```sh
cd kraken && go build -o kraken .
```

### Run

```sh
./dist/kraken -campaign campaigns/iot-standard.yaml \
              -cidrs "192.168.1.0/24" \
              -out kraken-results
```

### TUI

The TUI is a separate binary for interactive campaign management:

```sh
just kraken-tui-build
./dist/kraken-tui
```

## Evaluation Scenarios

Self-contained Docker environments that simulate real ICS/IoT deployments for testing:

| Scenario | Protocol | Domain |
|----------|----------|--------|
| **A** | MQTT | Smart Grid / SCADA |
| **B** | EtherCAT | Industrial Fieldbus |
| **C** | RTSP | Surveillance |

Scenario A supports security profiles (`insecure`, `partial`, `hardened`) that control how hardened the target is — `insecure` should produce many findings, `hardened` should produce few.

```sh
just scenario_run a insecure   # MQTT broker, no hardening
just scenario_run a hardened   # MQTT broker, locked down
just scenario_b_run            # EtherCAT fieldbus
```

## Output

Results are written to `{out}/{campaign_id}/{timestamp}/`:

```
kraken-results/scenario-a-mqtt/1772626401/
├── assessment.json              # All findings
├── assessment.success.json      # Successful findings only
├── runs/
│   └── 172.20.0.10_1883.json   # Per-target results
└── attack-trees/
    ├── summary.md               # Evaluation overview
    └── 172.20.0.10_1883.md      # Per-target tree + Mermaid graphs
```

## Components

| Component   | Description                                                                                           |
| ----------- | ----------------------------------------------------------------------------------------------------- |
| **Kraken**  | Orchestrator — scanning, scheduling, module execution, reporting                                      |
| **Trident** | Transport abstraction library with composable protocol stacks (TCP, TLS, UDP, DTLS, Raw IP, Ethernet) |

## Documentation

- [Kraken](docs/kraken/documentation.md) — Campaign orchestration, module APIs, attack trees
- [Trident](docs/trident/documentation.md) — Transport abstraction and conduit system
- [Module API](docs/MODULE.md) — How to write modules
- [Policy](docs/POLICY.md) — Execution policies and safety controls

## Testing

```sh
just test
# or
go test ./kraken/... ./trident/...
```
