# MQTT REPLAYER

This module is particularly usefull because it replays fixed mqtt packets sequences,
this is usefull to reproduce known bugs found in the past.

This module use the v1 API and takes as parameters a simple file path where the
packet sequence is saved (the packets are encoded in hex).

The parameter key to specify the sequence's file path is: `seq_file_path`.
It needs to be specified in the yaml and the path needs to be relative to where the
binary is run.

## Finding IDs

- **(dynamic)**: The finding ID is derived from the loaded sequence file name (without extension). For example, loading `CVE-2024-8376.txt` produces finding ID `CVE-2024-8376`.

## Example campaign step

```yaml
steps:
    - id: mqtt-replay
      type: lib
      api: 0
      required_tags: ["protocol:mqtt"]
      exec:
          abi:
              library_path: "./modules/protocols/mqtt/abi/mqtt_replay/build/mqtt_replay"
              symbol: "kraken_run"
      params:
          seq_file_path: "./modules/protocols/mqtt/abi/mqtt_replay/CVE-2024-8376.txt"
```
