# MQTT Boofuzz Fuzzer

This project is a grammar- and state-machine–based **MQTT 5** fuzzer built on top of [boofuzz](https://github.com/jtpereyda/boofuzz).

It models several MQTT control packets (CONNECT, PUBLISH, SUBSCRIBE, etc.) and drives them through a simple protocol flow against a target MQTT broker, while boofuzz applies its own mutation strategies to fuzz individual fields.

## Features

- MQTT 5 packet modelling via `build_mqtt_packet()`:
    - `CONNECT` (plain, with auth, with LWT)
    - `PUBLISH` (QoS 0 / 1 / 2)
    - `SUBSCRIBE` / `UNSUBSCRIBE`
    - `PINGREQ` / `DISCONNECT`
- Automatic computation of `Remaining Length` using an MQTT-compliant varint encoder.
- Simple **protocol state machine** using `session.connect()`:
    - Multiple flows starting from CONNECT -> SUBSCRIBE / PUBLISH / PING / etc.
- Callbacks for verifying broker responses:
    - `CONNACK`, `PUBACK`, `PUBREC/PUBREL/PUBCOMP`, `SUBACK`, `UNSUBACK`, `PINGRESP`
- Optional process monitoring via boofuzz `ProcessMonitor` / `ProcessMonitorLocal`.
- Logging to:
    - TUI, stdout, or file
    - Optional CSV log
- Automatic FSM graph rendering to `fsm.png`.

## Requirements

- Python 3.8+
- `pip` to install dependencies

Python packages:

- `boofuzz`
- `click`

System tools:

- [Graphviz](https://graphviz.org/) – used to generate the FSM PNG.

## Files & Outputs

- **Main script**: the file you posted (e.g. `mqtt_fuzzer.py`).
- **Output directory**:
    - By default: `./boofuzz-results`
    - Or: `<output-dir>/boofuzz-results` if you pass `--output-dir`.

Inside that directory you’ll typically get:

- `session.db` – boofuzz session database (test cases, crash info, etc.).
- `fuzz.log` – detailed text log of the fuzzing run (if `--file-dump`).
- `fsm.png` – rendered protocol state machine graph.
- Optionally: a CSV logfile (filename depends on the script; see `--csv-out`).

## Basic Usage

Run the fuzzer with the `fuzz` subcommand:

```bash
python mqtt_fuzzer.py fuzz --host 127.0.0.1 --port 1883
```

Where:

- `--host` – IP/hostname of the MQTT broker.
- `--port` – broker port (default in the script is `21`, but for MQTT you’ll usually want `1883` or `8883`).

The script will:

1. Build the MQTT message grammar and state machine.
2. Render the state machine graph to `boofuzz-results/fsm.png`.
3. Start fuzzing:
    - Boofuzz mutates various fields in CONNECT/PUBLISH/SUBSCRIBE/etc.
    - Callbacks check for the expected broker responses and log mismatches / timeouts.

## Command-Line Options

Here is a quick reference for the main options used by `fuzz`:

### Target connection

- `--host`
  Hostname or IP of the MQTT broker. (Required; you will be prompted if omitted.)

- `--port` _(int, default: 21)_
  TCP port of the broker. For standard MQTT use `1883`; for TLS `8883`, etc.

### Test case selection

- `--test-case-index` _(string)_
  Controls which test cases to run:
    - Omit: run all test cases.
    - Single number: run only that test case, e.g. `--test-case-index 42`.
    - Range: `start-end`, e.g. `--test-case-index 10-100`.
    - Open range: `-100` (from 1 to 100), or `50-` (from 50 to the end).

### Logging

- `--csv-out` _(path)_
  If provided, enables CSV logging to the specified file.

- `--sleep-between-cases` _(float, default: 0)_
  Wait time (in seconds) between test cases. Use this if the broker becomes unstable under rapid tests.

- `--tui / --no-tui`
  Enable/disable the curses-based TUI logger. (Mutually exclusive with some other log modes.)

- `--text-dump / --no-text-dump`
  Enable/disable simple text logging to stdout.

- `--file-dump / --no-file-dump` _(default: `True`)_
  Enable/disable logging to a file (typically `fuzz.log` in the output directory).

- `--output-dir` _(path)_
  Base directory for results. The fuzzer will create `<output-dir>/boofuzz-results` (or `./boofuzz-results` if not provided).

### Process monitoring

You can let boofuzz manage or monitor a local target process (e.g. a broker you want to fuzz).

- `--procmon-host`
  Host of a remote process monitor instance (if using remote monitoring).

- `--procmon-port` _(int, default: 26002 – boofuzz default)_
  Port for the process monitor.

- `--procmon-start` _(string)_
  Command used by the process monitor to start the target process.

- `--procmon-capture` _(flag)_
  Capture stdout/stderr of the target process on failures/crashes.

## Running a Specific Test Case

To reproduce a particular case (for example, after a crash):

```bash
python mqtt_fuzzer.py fuzz \
    --host 127.0.0.1 \
    --port 1883 \
    --test-case-index 123
```

This runs only test case #123

## Next Steps / Customization Ideas

- Adjust fuzzability of specific fields in the `variable_header` and `payload` definitions.
- Add more MQTT message types (AUTH, enhanced properties, etc.).
- Introduce custom strategies (e.g., seed-based mutation for payloads) on top of this grammar and state machine.
