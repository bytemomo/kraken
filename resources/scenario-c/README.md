# Scenario C: RTSP Video Surveillance - Kraken vs Baseline Comparison

Evaluates Kraken's orchestration value against standalone tools for RTSP camera security assessment.

## Evaluation Objectives

| Capability          | Question                                          | Success Criteria                                             |
| ------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| Orchestration value | What does Kraken provide beyond standalone tools? | Equivalent discovery + safety policies + structured findings |
| Tool integration    | Can existing tools be wrapped as Kraken modules?  | Tools execute via adapter; findings aggregate                |

## Baseline Tools

| Tool      | Type             | Capabilities                                           |
| --------- | ---------------- | ------------------------------------------------------ |
| nmap+NSE  | General-purpose  | Service detection, `rtsp-methods`, `rtsp-url-brute`    |
| Cameradar | RTSP-specialized | Path brute-force, credential attack, thumbnail capture |

## Kraken Differentiators

### 1. Safety Policies

Kraken enforces constraints that standalone tools lack:

```yaml
policy:
    safety:
        allow_aggressive: false # Prevents crashes on embedded devices
        require_max_duration: true # All tasks must have timeouts
        scope_enforcement: strict # No scanning outside defined CIDRs
    runner:
        max_parallel_targets: 3 # Limits concurrent operations
```

**Neither nmap nor Cameradar have equivalent safety guardrails.**

### 2. Structured Findings

| Aspect          | nmap     | Cameradar | Kraken                            |
| --------------- | -------- | --------- | --------------------------------- |
| Output format   | XML/text | JSON      | Unified JSON schema               |
| Finding IDs     | None     | None      | Standardized (RTSP-OPEN-PLAYBACK) |
| Severity levels | None     | None      | HIGH/MEDIUM/LOW/INFO              |
| Threat mapping  | Manual   | Manual    | Automatic attack-tree evaluation  |

### 3. Attack Tree Integration

Kraken maps findings directly to threat model:

```
S-1: UNAUTHORIZED STREAM ACCESS
├── RTSP-OPEN-PLAYBACK  →  Anonymous access allowed
└── DEFAULT-CREDENTIALS →  Factory credentials accepted
```

## Environment

3 IP cameras streaming via RTSP (no authentication):

| Camera   | IP          | Stream Path | Pattern |
| -------- | ----------- | ----------- | ------- |
| Entrance | 172.30.0.10 | /stream     | SMPTE   |
| Mid      | 172.30.0.11 | /stream     | Ball    |
| Exit     | 172.30.0.12 | /stream     | Snow    |

## Quick Start

```bash
# Start cameras
podman compose up -d

# Run all tools
./scripts/run-comparison.sh

# Or run individually:
podman compose --profile nmap up nmap-baseline
podman compose --profile cameradar up cameradar-baseline
podman compose --profile kraken up kraken
```

## Results

```
results/
├── nmap/                  # nmap XML/text output
│   ├── discovery_*.xml
│   ├── rtsp-methods_*.xml
│   └── rtsp-url-brute_*.xml
├── cameradar/             # Cameradar JSON output
│   └── cameradar_*.json
└── kraken/                # Structured findings + attack tree
    └── scenario-c-rtsp/
        ├── {target}/findings.json
        └── assessment.json
```

## Files

```
scenario-c/
├── docker-compose.yaml    # Cameras + baseline tools + kraken
├── campaign.yaml          # Kraken campaign with safety policies
├── attack-tree.yaml       # Threat-to-finding mappings
├── baseline/
│   ├── nmap-scan.sh       # nmap+NSE script
│   └── cameradar-scan.sh  # Cameradar script
├── scripts/
│   └── run-comparison.sh  # Run all tools
├── src/camera/
│   ├── Dockerfile
│   └── entrypoint.sh      # GStreamer RTSP server
└── results/
```

## Cleanup

```bash
podman compose down -v
rm -rf results/nmap/* results/cameradar/* results/kraken/*
```
