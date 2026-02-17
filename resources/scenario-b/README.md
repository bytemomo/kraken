# Scenario B: EtherCAT Fieldbus with KickCAT

EtherCAT simulation environment using [KickCAT](https://github.com/Siviuze/KickCAT).

## Components

- **Simulator**: KickCAT network simulator emulating EtherCAT slave(s)
- **Master**: Python-based EtherCAT master using KickCAT bindings
- **Kraken**: Security scanner (tools profile)
- **Capture**: tcpdump container for packet capture (tools profile)

## Quick Start

```bash
# 1. Create virtual ethernet pair
./scripts/setup-veth.sh create ecat

# 2a. Normal mode: master talks to simulator
sudo docker compose --profile default up --build

# 2b. Scanning mode: Kraken scans the simulator (no master)
sudo docker compose --profile tools up --build

# 3. Cleanup
sudo docker compose down
./scripts/setup-veth.sh delete ecat
```

Or use the Justfile from the project root:

```bash
just scenario_b_run
```

**Note:** The master and Kraken scanner cannot run simultaneously on the same
interface. Use `--profile default` for normal operation or `--profile tools`
for security scanning.

## Architecture

```
┌─────────────┐     veth pair      ┌─────────────┐
│   Master    │◄──── ecatA/B ─────►│  Simulator  │
│  (Python)   │                    │  (KickCAT)  │
└─────────────┘                    └─────────────┘
```

The master and simulator communicate via a virtual ethernet pair (`ecatA` <-> `ecatB`).
Both containers use host networking to access the veth interfaces.

## Files

```
scenario-b/
├── docker-compose.yaml     # Container orchestration
├── campaign.yaml           # Kraken campaign definition
├── attack-tree.yaml        # EtherCAT threat model
├── scripts/
│   └── setup-veth.sh       # veth pair management
├── src/
│   ├── master/
│   │   ├── Dockerfile
│   │   └── easycat.py      # EtherCAT master script
│   └── simulator/
│       ├── Dockerfile
│       ├── network_simulator.cc
│       ├── foot.bin        # EEPROM image
│       └── foot.xml        # ESI device description
└── captures/               # tcpdump captures
```

## Simulator Capabilities

The KickCAT simulator supports:

- EEPROM loading from binary files
- ESI (EtherCAT Slave Information) parsing
- Sync Manager emulation
- FMMU emulation
- CoE mailbox (SDO read/write)
- PDO data exchange

**Not supported:**

- Distributed clocks (DC)
- Hardware interrupts
- Redundancy

## Packet Capture

To capture EtherCAT traffic:

```bash
# Start capture container
sudo docker compose --profile tools up -d capture

# Run tcpdump
sudo docker exec scenario-b-capture tcpdump -i ecatA -w /captures/ethercat.pcap

# Open in Wireshark
wireshark captures/ethercat.pcap
```

## References

- [KickCAT GitHub](https://github.com/Siviuze/KickCAT)
- [EtherCAT Technology Group](https://www.ethercat.org/)
