# mqtt_acl_probe (ABI v2)

Probes MQTT ACLs by iterating credentials (or anonymous) and checking:

- CONNECT acceptance
- SUBSCRIBE to a probe topic (QoS 0)
- PUBLISH to the same topic (QoS 1, expect PUBACK)

Uses ABI v2 `open/close` to establish a fresh connection per credential.

## Parameters

- `creds_file` (optional): path to `username:password` lines. If omitted, only anonymous is tested.
- `topic` (optional): probe topic. Default `kraken/acl/probe`.
- `timeout_ms` (optional): per-connection timeout in milliseconds. Default 5000.

## Usage (campaign snippet)

```yaml
steps:
    - id: mqtt-acl-probe
      type: lib
      api: 1
      required_tags: ["protocol:mqtt"]
      exec:
          abi:
              library_path: "./modules/protocols/mqtt/abi/mqtt_acl_probe/build/mqtt_acl_probe"
              symbol: "kraken_run_v2"
          conduit:
              kind: 1
              stack:
                  - name: tcp
                  - name: tls # optional
                    params:
                        skip_verify: true
      params:
          creds_file: "./wordlists/mqtt.txt"
          topic: "kraken/acl/probe"
          timeout_ms: 5000
```

## Finding IDs

- `MQTT-ACL-SUB`: SUBSCRIBE accepted for the probe topic.
- `MQTT-ACL-PUB`: PUBLISH accepted (PUBACK received) for the probe topic.
