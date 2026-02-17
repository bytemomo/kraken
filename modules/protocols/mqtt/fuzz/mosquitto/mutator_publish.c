/*
 * AFL++ Custom Mutator for MQTT PUBLISH packets
 *
 * Generates structurally valid PUBLISH packets to reach deeper code paths.
 * PUBLISH format:
 *   [2-byte topic length][topic string][2-byte packet ID (QoS>0)][properties (MQTT5)][payload]
 *
 * Build: clang -shared -fPIC -O2 -Wall mutator_publish.c -o mutator_publish.so
 * Usage: AFL_CUSTOM_MUTATOR_LIBRARY=./mutator_publish.so afl-fuzz ...
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t *buf;
  size_t buf_size;
  unsigned int seed;
} mutator_t;

/* MQTT 5.0 PUBLISH property identifiers */
#define PROP_PAYLOAD_FORMAT       0x01
#define PROP_MESSAGE_EXPIRY       0x02
#define PROP_TOPIC_ALIAS          0x23
#define PROP_RESPONSE_TOPIC       0x08
#define PROP_CORRELATION_DATA     0x09
#define PROP_USER_PROPERTY        0x26
#define PROP_SUBSCRIPTION_ID      0x0B
#define PROP_CONTENT_TYPE         0x03

/* Harness config flags (byte 0 of input) */
#define CFG_RETAIN_AVAILABLE      0x01

static uint32_t xorshift32(uint32_t *state) {
  uint32_t x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

static size_t write_u16(uint8_t *buf, uint16_t val) {
  buf[0] = (val >> 8) & 0xFF;
  buf[1] = val & 0xFF;
  return 2;
}

static size_t write_string(uint8_t *buf, const char *str, size_t len) {
  write_u16(buf, (uint16_t)len);
  memcpy(buf + 2, str, len);
  return 2 + len;
}

static size_t write_varint(uint8_t *buf, uint32_t val) {
  size_t len = 0;
  do {
    uint8_t byte = val & 0x7F;
    val >>= 7;
    if (val > 0) byte |= 0x80;
    buf[len++] = byte;
  } while (val > 0 && len < 4);
  return len;
}

void *afl_custom_init(void *afl, unsigned int seed) {
  (void)afl;
  mutator_t *m = calloc(1, sizeof(mutator_t));
  if (!m) return NULL;
  m->seed = seed;
  m->buf_size = 8192;
  m->buf = malloc(m->buf_size);
  if (!m->buf) {
    free(m);
    return NULL;
  }
  return m;
}

void afl_custom_deinit(void *data) {
  mutator_t *m = data;
  if (m) {
    free(m->buf);
    free(m);
  }
}

/* Generate MQTT 5.0 PUBLISH properties block */
static size_t generate_publish_properties(uint8_t *buf, size_t max_len, uint32_t *rng) {
  uint8_t props[256];
  size_t props_len = 0;
  uint32_t prop_mask = xorshift32(rng);

  /* Payload Format Indicator (1 byte: 0=bytes, 1=UTF-8) */
  if ((prop_mask & 0x01) && props_len + 2 < sizeof(props)) {
    props[props_len++] = PROP_PAYLOAD_FORMAT;
    props[props_len++] = xorshift32(rng) & 0x01;
  }

  /* Message Expiry Interval (4 bytes) */
  if ((prop_mask & 0x02) && props_len + 5 < sizeof(props)) {
    props[props_len++] = PROP_MESSAGE_EXPIRY;
    uint32_t expiry = xorshift32(rng);
    props[props_len++] = (expiry >> 24) & 0xFF;
    props[props_len++] = (expiry >> 16) & 0xFF;
    props[props_len++] = (expiry >> 8) & 0xFF;
    props[props_len++] = expiry & 0xFF;
  }

  /* Topic Alias (2 bytes) - important for coverage */
  if ((prop_mask & 0x04) && props_len + 3 < sizeof(props)) {
    props[props_len++] = PROP_TOPIC_ALIAS;
    uint16_t alias = (xorshift32(rng) % 20) + 1; /* 1-20, 0 is invalid */
    props[props_len++] = (alias >> 8) & 0xFF;
    props[props_len++] = alias & 0xFF;
  }

  /* Response Topic (string) */
  if ((prop_mask & 0x08) && props_len + 20 < sizeof(props)) {
    props[props_len++] = PROP_RESPONSE_TOPIC;
    const char *topics[] = {"response/topic", "reply", "ack/path"};
    const char *topic = topics[xorshift32(rng) % 3];
    props_len += write_string(&props[props_len], topic, strlen(topic));
  }

  /* Correlation Data (binary) */
  if ((prop_mask & 0x10) && props_len + 10 < sizeof(props)) {
    props[props_len++] = PROP_CORRELATION_DATA;
    uint8_t corr[] = {0x01, 0x02, 0x03, 0x04};
    props_len += write_string(&props[props_len], (char *)corr, sizeof(corr));
  }

  /* User Property (string pair) */
  if ((prop_mask & 0x20) && props_len + 25 < sizeof(props)) {
    props[props_len++] = PROP_USER_PROPERTY;
    const char *key = "fuzz-key";
    const char *val = "fuzz-val";
    props_len += write_string(&props[props_len], key, strlen(key));
    props_len += write_string(&props[props_len], val, strlen(val));
  }

  /* Subscription Identifier (varint) */
  if ((prop_mask & 0x40) && props_len + 5 < sizeof(props)) {
    props[props_len++] = PROP_SUBSCRIPTION_ID;
    props_len += write_varint(&props[props_len], (xorshift32(rng) % 268435455) + 1);
  }

  /* Content Type (string) */
  if ((prop_mask & 0x80) && props_len + 20 < sizeof(props)) {
    props[props_len++] = PROP_CONTENT_TYPE;
    const char *types[] = {"application/json", "text/plain", "application/octet-stream"};
    const char *type = types[xorshift32(rng) % 3];
    props_len += write_string(&props[props_len], type, strlen(type));
  }

  /* Write varint length + properties */
  if (props_len == 0) {
    buf[0] = 0;
    return 1;
  }

  size_t hdr_len = write_varint(buf, (uint32_t)props_len);
  if (hdr_len + props_len > max_len) {
    buf[0] = 0;
    return 1;
  }
  memcpy(buf + hdr_len, props, props_len);
  return hdr_len + props_len;
}

static size_t generate_publish(uint8_t *buf, size_t max_len, uint32_t *rng) {
  if (max_len < 32) return 0;

  size_t pos = 0;
  uint32_t r = xorshift32(rng);

  /*
   * Harness control bytes:
   *   byte 0: config flags (controls broker config options)
   *     bit 0: retain_available - allows retained messages
   *   byte 1: QoS (bits 1-2), retain (bit 0), dup (bit 3)
   *   byte 2: protocol version selector (< 128 = MQTT 3.1.1, >= 128 = MQTT 5.0)
   */

  /* Config flags - vary to explore both enabled/disabled paths */
  uint8_t config_flags = 0;
  if (xorshift32(rng) & 0x01) config_flags |= CFG_RETAIN_AVAILABLE;
  buf[pos++] = config_flags;

  /* QoS/retain/dup flags */
  uint8_t qos = r % 3;  /* 0, 1, or 2 */
  /*
   * Generate retain flag more often when retain_available is set,
   * to properly exercise the retain handling code path.
   */
  uint8_t retain;
  if (config_flags & CFG_RETAIN_AVAILABLE) {
    retain = (r >> 2) & 0x01;  /* 50% chance */
  } else {
    retain = ((r >> 2) % 4) == 0 ? 1 : 0;  /* 25% chance - test error path */
  }
  uint8_t dup = (qos > 0) ? ((r >> 3) & 0x01) : 0;  /* DUP only valid for QoS > 0 */
  buf[pos++] = (dup << 3) | (qos << 1) | retain;

  /* Protocol version: mix MQTT 3.1.1 and 5.0 */
  uint8_t mqtt5 = (r >> 4) & 0x01;
  buf[pos++] = mqtt5 ? 200 : 50;  /* >= 128 = MQTT5, < 128 = MQTT 3.1.1 */

  /*
   * PUBLISH payload structure:
   *   [2-byte topic length][topic][2-byte packet ID if QoS>0][properties if MQTT5][payload]
   */

  /* Topic - must be valid UTF-8 and pass mosquitto_pub_topic_check() */
  const char *topics[] = {
    /* Standard topics */
    "test/topic",
    "sensors/temperature",
    "home/living/light",
    "device/status",
    "data/stream",
    /* Edge cases */
    "/",                      /* Root */
    "/leading/slash",         /* Leading slash */
    "trailing/slash/",        /* Trailing slash */
    "a",                      /* Single char */
    "a/b/c/d/e/f/g/h",        /* Deep nesting */
    /* Special prefixes - trigger different code paths */
    "$SYS/broker/load",       /* System topic */
    "$CONTROL/dynamic",       /* Control topic (if WITH_CONTROL) */
    "$share/group/topic",     /* Shared subscription format (invalid for pub) */
    /* Unicode (valid UTF-8) */
    "sensor/\xC3\xA9\xC3\xA0", /* sensor/éà */
    /* Topics that should trigger ACL checks */
    "admin/config",
    "private/data",
  };
  int topic_idx = xorshift32(rng) % (sizeof(topics) / sizeof(topics[0]));
  const char *topic = topics[topic_idx];
  size_t topic_len = strlen(topic);

  /* Sometimes use empty topic (valid in MQTT5 with topic alias) */
  if (mqtt5 && (xorshift32(rng) % 10) == 0) {
    topic = "";
    topic_len = 0;
  }

  pos += write_string(&buf[pos], topic, topic_len);

  /* Packet ID (only for QoS 1 or 2) */
  if (qos > 0) {
    uint16_t packet_id = (xorshift32(rng) % 65534) + 1;  /* 1-65535, 0 is invalid */
    pos += write_u16(&buf[pos], packet_id);
  }

  /* MQTT 5.0 Properties */
  if (mqtt5) {
    pos += generate_publish_properties(&buf[pos], max_len - pos - 100, rng);
  }

  /* Payload - variable content */
  const char *payloads[] = {
    "test payload",
    "{\"value\": 42}",
    "Hello, World!",
    "",                       /* Empty payload */
    "\x00\x01\x02\x03",       /* Binary */
  };
  int payload_idx = xorshift32(rng) % (sizeof(payloads) / sizeof(payloads[0]));
  const char *payload = payloads[payload_idx];
  size_t payload_len = (payload_idx == 4) ? 4 : strlen(payload);

  /* Sometimes generate larger payload */
  if ((xorshift32(rng) % 5) == 0 && pos + 200 < max_len) {
    payload_len = 100 + (xorshift32(rng) % 100);
    memset(&buf[pos], 'A', payload_len);
    pos += payload_len;
  } else {
    memcpy(&buf[pos], payload, payload_len);
    pos += payload_len;
  }

  return pos;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  mutator_t *m = data;
  (void)buf; (void)buf_size; (void)add_buf; (void)add_buf_size;

  m->seed = m->seed * 1103515245 + 12345;
  uint32_t rng = m->seed;

  /* 85% generate structured, 15% let AFL do random havoc */
  if ((rng % 100) < 85) {
    size_t len = generate_publish(m->buf, m->buf_size < max_size ? m->buf_size : max_size, &rng);
    if (len > 0) {
      *out_buf = m->buf;
      return len;
    }
  }

  *out_buf = NULL;
  return 0;
}

size_t afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size,
                                uint8_t **out_buf) {
  (void)data;
  *out_buf = buf;
  return buf_size;
}

const char *afl_custom_describe(void *data, size_t max_len) {
  (void)data; (void)max_len;
  return "mqtt-publish";
}
