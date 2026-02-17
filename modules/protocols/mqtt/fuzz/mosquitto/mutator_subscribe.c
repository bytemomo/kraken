/*
 * AFL++ Custom Mutator for MQTT SUBSCRIBE packets
 *
 * Generates structurally valid SUBSCRIBE packets to reach deeper code paths.
 * SUBSCRIBE format:
 *   [2-byte packet ID][properties (MQTT5)][topic filter 1][options 1][topic filter 2][options 2]...
 *
 * Build: clang -shared -fPIC -O2 -Wall mutator_subscribe.c -o mutator_subscribe.so
 * Usage: AFL_CUSTOM_MUTATOR_LIBRARY=./mutator_subscribe.so afl-fuzz ...
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

/* MQTT 5.0 SUBSCRIBE property identifiers */
#define PROP_SUBSCRIPTION_ID      0x0B
#define PROP_USER_PROPERTY        0x26

/* Harness config flags (byte 0 of input) */
#define CFG_RETAIN_AVAILABLE      0x01

/* Subscription options bits (MQTT 5.0) */
#define SUB_OPT_QOS_MASK          0x03
#define SUB_OPT_NO_LOCAL          0x04
#define SUB_OPT_RETAIN_AS_PUB     0x08
#define SUB_OPT_RETAIN_HANDLING_0 0x00
#define SUB_OPT_RETAIN_HANDLING_1 0x10
#define SUB_OPT_RETAIN_HANDLING_2 0x20

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

/* Generate MQTT 5.0 SUBSCRIBE properties block */
static size_t generate_subscribe_properties(uint8_t *buf, size_t max_len, uint32_t *rng) {
  uint8_t props[128];
  size_t props_len = 0;
  uint32_t prop_mask = xorshift32(rng);

  /* Subscription Identifier (varint, 1-268435455) */
  if ((prop_mask & 0x01) && props_len + 5 < sizeof(props)) {
    props[props_len++] = PROP_SUBSCRIPTION_ID;
    uint32_t sub_id = (xorshift32(rng) % 268435454) + 1; /* 1 to max, 0 is invalid */
    props_len += write_varint(&props[props_len], sub_id);
  }

  /* User Property (string pair) */
  if ((prop_mask & 0x02) && props_len + 25 < sizeof(props)) {
    props[props_len++] = PROP_USER_PROPERTY;
    const char *key = "sub-key";
    const char *val = "sub-val";
    props_len += write_string(&props[props_len], key, strlen(key));
    props_len += write_string(&props[props_len], val, strlen(val));
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

/* Generate a single topic filter with subscription options */
static size_t generate_topic_filter(uint8_t *buf, size_t max_len, uint32_t *rng, int mqtt5) {
  if (max_len < 10) return 0;

  size_t pos = 0;

  /* Topic filters - including wildcards and special prefixes */
  const char *filters[] = {
    /* Standard topics */
    "sensors/#",
    "home/+/temperature",
    "device/status",
    "+/data/#",
    "#",
    /* Single level wildcard variations */
    "+",
    "a/+/b/+/c",
    "+/+/+",
    /* Multi-level wildcard variations */
    "test/#",
    "a/b/c/#",
    /* Shared subscriptions (MQTT 5.0) */
    "$share/group1/sensors/#",
    "$share/mygroup/home/+/temp",
    "$share/g/+",
    /* System topics */
    "$SYS/#",
    "$SYS/broker/+",
    /* Edge cases */
    "/",                        /* Root */
    "/a/b/c",                   /* Leading slash */
    "a/b/c/",                   /* Trailing slash */
    "a//b",                     /* Empty level */
    /* Long topic */
    "level1/level2/level3/level4/level5/level6/level7/level8",
    /* Unicode (valid UTF-8) */
    "sensor/\xC3\xA9\xC3\xA0/#",
  };

  int filter_idx = xorshift32(rng) % (sizeof(filters) / sizeof(filters[0]));
  const char *filter = filters[filter_idx];
  size_t filter_len = strlen(filter);

  pos += write_string(&buf[pos], filter, filter_len);

  /* Subscription options byte */
  uint8_t options = 0;
  uint32_t opt_bits = xorshift32(rng);

  /* QoS (0, 1, or 2) */
  options |= (opt_bits & SUB_OPT_QOS_MASK) % 3;

  if (mqtt5) {
    /* MQTT 5.0 specific options */
    if (opt_bits & 0x04) options |= SUB_OPT_NO_LOCAL;
    if (opt_bits & 0x08) options |= SUB_OPT_RETAIN_AS_PUB;

    /* Retain handling (0, 1, or 2) */
    uint8_t retain_handling = ((opt_bits >> 4) % 3) << 4;
    options |= retain_handling;
  }

  buf[pos++] = options;

  return pos;
}

static size_t generate_subscribe(uint8_t *buf, size_t max_len, uint32_t *rng) {
  if (max_len < 32) return 0;

  size_t pos = 0;
  uint32_t r = xorshift32(rng);

  /*
   * Harness control bytes:
   *   byte 0: config flags (controls broker config options)
   *     bit 0: retain_available - allows retained message delivery on subscribe
   *   byte 1: protocol version selector (< 85 = 3.1, 85-169 = 3.1.1, >= 170 = 5.0)
   */

  /* Config flags - vary to explore both enabled/disabled paths */
  uint8_t config_flags = 0;
  if (xorshift32(rng) & 0x01) config_flags |= CFG_RETAIN_AVAILABLE;
  buf[pos++] = config_flags;

  int mqtt5 = ((r >> 8) & 0xFF) >= 170;
  buf[pos++] = mqtt5 ? 200 : ((r >> 8) % 170);  /* Protocol selector */

  /*
   * SUBSCRIBE payload structure:
   *   [2-byte packet ID][properties if MQTT5][topic filter + options]...
   */

  /* Packet ID (1-65535, 0 is invalid) */
  uint16_t packet_id = (xorshift32(rng) % 65534) + 1;
  pos += write_u16(&buf[pos], packet_id);

  /* MQTT 5.0 Properties */
  if (mqtt5) {
    pos += generate_subscribe_properties(&buf[pos], max_len - pos - 100, rng);
  }

  /* Generate 1-4 topic filters */
  int num_filters = (xorshift32(rng) % 4) + 1;
  for (int i = 0; i < num_filters && pos + 50 < max_len; i++) {
    pos += generate_topic_filter(&buf[pos], max_len - pos, rng, mqtt5);
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
    size_t len = generate_subscribe(m->buf, m->buf_size < max_size ? m->buf_size : max_size, &rng);
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
  return "mqtt-subscribe";
}
