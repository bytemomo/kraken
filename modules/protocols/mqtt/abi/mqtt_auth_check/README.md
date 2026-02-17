# mqtt_auth_check (ABI v2)

Checks MQTT authentication posture using the ABI v2 conduit (runner provides the connection). It verifies anonymous CONNECT acceptance and basic pub/sub permissions. With v2 reconnection support, credentials can be tested on fresh conduits per attempt.

## Parameters

- `creds_file` (optional): path to a username:password list. Each entry will be tested with a fresh conduit.

## Usage (campaign snippet)

```yaml
steps:
    - id: mqtt-auth-check-v2
      type: lib
      api: 1
      required_tags: ["protocol:mqtt"]
      exec:
          abi:
              library_path: "./modules/protocols/mqtt/abi/mqtt_auth_check/build/mqtt_auth_check_v2"
              symbol: "kraken_run_v2"
          conduit:
              kind: 1
              stack:
                  - name: tcp
                  - name: tls # optional, remove if plaintext
                    params:
                        skip_verify: true
      params:
          creds_file: "./wordlists/mqtt.txt"
```

## Finding IDs

- `MQTT-ANON`: Anonymous authentication accepted by the broker.
- `MQTT-PUBSUB-ANON`: Anonymous publish/subscribe allowed.
- `MQTT-WEAK-CREDS`: Weak/default credentials accepted (when testing credentials from file).

## Notes

- Findings include anonymous CONNECT and publish/subscribe acceptance when the broker allows it.
