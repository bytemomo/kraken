# Mosquitto MQTT Fuzzer

AFL++ fuzzing harnesses for Eclipse Mosquitto MQTT broker/client (v2.1.0).

## Fuzzing Targets

| Target        | Description               |
| ------------- | ------------------------- |
| `connect`     | Broker CONNECT handler    |
| `publish`     | Broker PUBLISH handler    |
| `subscribe`   | Broker SUBSCRIBE handler  |
| `property`    | MQTT 5.0 property parsing |
| `packet_read` | Client packet parsing     |

## Architecture Decisions

### Why These Targets?

**Broker handlers (connect, publish, subscribe)** are the primary attack surface:

- Process untrusted network input directly
- CONNECT is pre-authentication - bugs here are exploitable without credentials
- PUBLISH/SUBSCRIBE handle complex topic validation and ACL checks
- Combined ~2000 lines of parsing code with many edge cases

**Property parsing** is a secondary target:

- MQTT 5.0 added properties to most packet types
- Complex varint + type-length-value parsing
- 7 different property types with attacker-controlled lengths

**packet_read** covers the client library for malicious broker scenarios.

### Input Format Design

Each broker harness uses a **control byte prefix** to enable fuzz-controlled configuration:

```
connect:   [config:1][CONNECT payload...]
publish:   [config:1][qos_flags:1][protocol:1][PUBLISH payload...]
subscribe: [config:1][protocol:1][SUBSCRIBE payload...]
```

**Why a control byte instead of hardcoded config?**

The broker has config options that gate different code paths:

- `retain_available` - enables/disables retained message handling
- `allow_zero_length_clientid` - accepts/rejects empty client IDs
- `allow_anonymous` - bypasses/enforces authentication

Hardcoding these means the fuzzer only explores one path. By making them fuzz-controlled:

1. AFL++ discovers that flipping control byte bits causes different coverage
2. Corpus naturally splits into variants covering all config combinations
3. Both "feature enabled" and "feature disabled" error paths get tested

**Config byte layout:**

| Harness   | Bit 0            | Bit 1                      | Bit 2           |
| --------- | ---------------- | -------------------------- | --------------- |
| connect   | retain_available | allow_zero_length_clientid | allow_anonymous |
| publish   | retain_available | -                          | -               |
| subscribe | retain_available | -                          | -               |

### Custom Mutators

Structure-aware mutators in `mutator_*.c` generate valid MQTT packets:

- **mutator_connect.c** - Generates CONNECT with varied protocol versions, flags, properties
- **mutator_publish.c** - Generates PUBLISH with topics, QoS levels, MQTT5 properties
- **mutator_subscribe.c** - Generates SUBSCRIBE with wildcards, shared subscriptions

**Why custom mutators?**

MQTT packets have structure: length-prefixed strings, varints, interdependent fields. Random bit-flipping rarely produces valid packets that reach deep code paths.

The mutators:

1. Generate structurally valid packets (85% of mutations)
2. Let AFL++ havoc handle corruption (15% of mutations)
3. Include the control byte with semantic awareness (e.g., generate empty client IDs more often when `allow_zero_length_clientid` is set)

**Mutator-config correlation:**

The mutators understand the config byte semantics:

- When `retain_available=true`, generate retain flags more often to exercise retain handling
- When `allow_zero_length_clientid=true`, generate empty client IDs more often
- This ensures both success and error paths get proper coverage

### Plugin Callback Registration Fix

**Problem discovered:** The broker harnesses initially achieved only ~5% bitmap coverage.

**Root cause:** `mosquitto_callback_register()` silently fails if `security_option_count == 0`. The harnesses were doing:

```c
secopts->pid = calloc(1, sizeof(mosquitto_plugin_id_t));  // count stays 0
```

This caused:

- Auth callbacks never registered
- CONNECT always failed authentication (never reached `connect__on_authorised()`)
- ACL callbacks never registered for PUBLISH/SUBSCRIBE

**Fix:**

```c
secopts->pid->config.security_option_count = 1;
secopts->pid->config.security_options = malloc(sizeof(void*));
secopts->pid->config.security_options[0] = secopts;
mosquitto_callback_register(secopts->pid, MOSQ_EVT_BASIC_AUTH, ...);
```

**Impact:** Coverage improved from ~10% to ~18% for handle_connect.c after this fix.

### Coverage Results

After implementing control bytes + mutator awareness + callback fix:

| Harness   | Target File        | Coverage | Previous |
| --------- | ------------------ | -------- | -------- |
| connect   | handle_connect.c   | 16.83%   | 10.24%   |
| publish   | handle_publish.c   | 38.52%   | 12.70%   |
| subscribe | handle_subscribe.c | 32.24%   | 9.54%    |
| property  | property_mosq.c    | 38.79%   | 38.79%   |

## Usage

### Basic Fuzzing

```bash
# With custom mutator (recommended)
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp -m fuzz connect
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp -m fuzz publish
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp -m fuzz subscribe

# Without custom mutator
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp fuzz property
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp fuzz packet_read
```

### Coverage Analysis

```bash
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp cov connect
```

### Crash Reproduction

```bash
podman run --rm -v ./output:/work/output mosquitto-fuzz:aflpp repro connect /work/output/connect/crashes/id:000000*
```

### Options

```
$ podman run --rm -it mosquitto-fuzz:aflpp --help
Mosquitto Fuzzer

Usage: entrypoint.sh [OPTIONS] <MODE> [TARGET] [EXTRA_ARGS...]

Modes:
  fuzz          - AFL++ fuzzing with JSON results (default)
  report        - Collect and output JSON results from previous run
  repro         - Reproduce a crash file (requires crash file as extra arg)
  minimize      - Minimize a crash file (requires crash file as extra arg)
  cov           - Run coverage on seed corpus
  shell         - Start interactive shell
  list          - List available fuzzers

Targets:
  packet_read   - Client packet parsing (default)
  connect       - Broker CONNECT handler
  publish       - Broker PUBLISH handler
  subscribe     - Broker SUBSCRIBE handler
  property      - MQTT 5.0 property parsing

Options:
  -t, --timeout SEC    Fuzzing timeout in seconds (default: 300)
  -g, --gui            Show AFL++ interactive GUI instead of JSON output
  -r, --resume         Resume a previous fuzzing run
  -m, --mutator        Use custom structure-aware mutator (connect only)
  -o, --output DIR     Output directory (default: /work/output)
  -c, --corpus DIR     Corpus directory (default: /work/corpus)
  -h, --help           Show this help

Examples:
  entrypoint.sh fuzz connect                     # JSON output after 300s
  entrypoint.sh -t 60 fuzz packet_read           # JSON output after 60s
  entrypoint.sh -g fuzz connect                  # Interactive GUI mode
  entrypoint.sh -r fuzz connect                  # Resume previous run
  entrypoint.sh -m fuzz connect                  # Use custom MQTT mutator
  entrypoint.sh repro connect /path/to/crash
```

## Files

```
├── harness_broker_connect.c   # CONNECT handler harness
├── harness_broker_publish.c   # PUBLISH handler harness
├── harness_broker_subscribe.c # SUBSCRIBE handler harness
├── harness_property_parse.c   # MQTT5 property parser harness
├── harness_packet_read.c      # Client packet parser harness
├── mutator_connect.c          # Structure-aware CONNECT mutator
├── mutator_publish.c          # Structure-aware PUBLISH mutator
├── mutator_subscribe.c        # Structure-aware SUBSCRIBE mutator
├── Dockerfile                 # AFL++ build environment
├── entrypoint.sh              # Container entrypoint
└── README.md
```

## Build Configuration

All harnesses built with:

- **AFL++ LTO mode** - Link-time instrumentation for better coverage tracking
- **AddressSanitizer** - Buffer overflow, use-after-free detection
- **UndefinedBehaviorSanitizer** - Integer overflow, null deref detection

Coverage builds use LLVM source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`).
