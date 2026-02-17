# MQTT \$SYS TOPIC DISCLOSURE

This module will check that subscribing to \# do not get also \$SYS related topics
as this can enable an attacker (that have access to a client) to learn informations
about the system (e.g. connections, topics etc..).

## General Info

This module will:

1. open a connection to the broker as a subscriber and will subscribe
   to # topic.
2. open a connection to the broker as a publisher and publish to a random topic
   to trigger the update of $SYS topics.
3. See if the subscriber gets the $SYS topic update.

In the case in which the $SYS topic update is reached it flags the findings as true.

## Finding IDs

- `mqtt-sys-disclosure`: Emitted when $SYS topic information is leaked to the subscriber.

## Parameters

- `username` / `password` (optional): credentials for both publisher and subscriber.
- `sys_prefix` (optional, default `$SYS/`): custom sys-topic prefix to watch.
- Evidence includes leaked topic and a hex-encoded payload preview when observed.

## Usage (campaign snippet)

```yaml
steps:
    - id: mqtt-sys-disclosure
      type: lib
      api: 0
      required_tags: ["protocol:mqtt"]
      exec:
          abi:
              library_path: "./modules/protocols/mqtt/abi/mqtt_sys_disclosure/build/mqtt_sys_disclosure"
              symbol: "kraken_run"
      params:
          username: "probe"
          password: "probe"
          sys_prefix: "$SYS/"
```
