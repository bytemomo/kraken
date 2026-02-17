/*
 * AFL++ Custom Mutator for MQTT CONNECT packets
 *
 * Generates structurally valid CONNECT packets to reach deeper code paths.
 * Understands MQTT 3.1, 3.1.1, and 5.0 formats.
 *
 * Build: afl-clang-fast -shared -fPIC -o mutator_connect.so mutator_connect.c
 * Usage: AFL_CUSTOM_MUTATOR_LIBRARY=./mutator_connect.so afl-fuzz ...
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* AFL++ custom mutator API */
typedef struct {
  uint8_t *buf;
  size_t buf_size;
  unsigned int seed;
} mutator_t;

/* MQTT protocol constants */
#define MQTT_PROTO_31    3
#define MQTT_PROTO_311   4
#define MQTT_PROTO_5     5

/* Connect flags */
#define FLAG_CLEAN_START  0x02
#define FLAG_WILL         0x04
#define FLAG_WILL_QOS0    0x00
#define FLAG_WILL_QOS1    0x08
#define FLAG_WILL_QOS2    0x10
#define FLAG_WILL_RETAIN  0x20
#define FLAG_PASSWORD     0x40
#define FLAG_USERNAME     0x80

/* Harness config flags (byte 0 of input) */
#define CFG_RETAIN_AVAILABLE         0x01
#define CFG_ALLOW_ZERO_LEN_CLIENTID  0x02
#define CFG_ALLOW_ANONYMOUS          0x04

/* MQTT 5.0 property identifiers */
#define PROP_SESSION_EXPIRY       0x11
#define PROP_RECEIVE_MAX          0x21
#define PROP_MAX_PACKET_SIZE      0x27
#define PROP_TOPIC_ALIAS_MAX      0x22
#define PROP_REQUEST_RESPONSE     0x19
#define PROP_REQUEST_PROBLEM      0x17
#define PROP_USER_PROPERTY        0x26
#define PROP_AUTH_METHOD          0x15
#define PROP_AUTH_DATA            0x16

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
  mutator_t *m = calloc(1, sizeof(mutator_t));
  if (!m) return NULL;
  m->seed = seed;
  m->buf_size = 4096;
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

/* Generate MQTT 5.0 properties block */
static size_t generate_properties(uint8_t *buf, size_t max_len, uint32_t *rng) {
  uint8_t props[256];
  size_t props_len = 0;
  uint32_t prop_mask = xorshift32(rng);

  /* Session Expiry Interval (4 bytes) */
  if ((prop_mask & 0x01) && props_len + 5 < sizeof(props)) {
    props[props_len++] = PROP_SESSION_EXPIRY;
    uint32_t expiry = xorshift32(rng);
    props[props_len++] = (expiry >> 24) & 0xFF;
    props[props_len++] = (expiry >> 16) & 0xFF;
    props[props_len++] = (expiry >> 8) & 0xFF;
    props[props_len++] = expiry & 0xFF;
  }

  /* Receive Maximum (2 bytes) */
  if ((prop_mask & 0x02) && props_len + 3 < sizeof(props)) {
    props[props_len++] = PROP_RECEIVE_MAX;
    uint16_t recv_max = (xorshift32(rng) % 65535) + 1;
    props[props_len++] = (recv_max >> 8) & 0xFF;
    props[props_len++] = recv_max & 0xFF;
  }

  /* Maximum Packet Size (4 bytes) */
  if ((prop_mask & 0x04) && props_len + 5 < sizeof(props)) {
    props[props_len++] = PROP_MAX_PACKET_SIZE;
    uint32_t max_pkt = xorshift32(rng);
    props[props_len++] = (max_pkt >> 24) & 0xFF;
    props[props_len++] = (max_pkt >> 16) & 0xFF;
    props[props_len++] = (max_pkt >> 8) & 0xFF;
    props[props_len++] = max_pkt & 0xFF;
  }

  /* Topic Alias Maximum (2 bytes) */
  if ((prop_mask & 0x08) && props_len + 3 < sizeof(props)) {
    props[props_len++] = PROP_TOPIC_ALIAS_MAX;
    uint16_t alias_max = xorshift32(rng) & 0xFFFF;
    props[props_len++] = (alias_max >> 8) & 0xFF;
    props[props_len++] = alias_max & 0xFF;
  }

  /* Request Response Information (1 byte) */
  if ((prop_mask & 0x10) && props_len + 2 < sizeof(props)) {
    props[props_len++] = PROP_REQUEST_RESPONSE;
    props[props_len++] = xorshift32(rng) & 0x01;
  }

  /* Request Problem Information (1 byte) */
  if ((prop_mask & 0x20) && props_len + 2 < sizeof(props)) {
    props[props_len++] = PROP_REQUEST_PROBLEM;
    props[props_len++] = xorshift32(rng) & 0x01;
  }

  /* User Property (string pair) */
  if ((prop_mask & 0x40) && props_len + 20 < sizeof(props)) {
    props[props_len++] = PROP_USER_PROPERTY;
    const char *key = "fuzz-key";
    const char *val = "fuzz-val";
    props_len += write_string(&props[props_len], key, strlen(key));
    props_len += write_string(&props[props_len], val, strlen(val));
  }

  /* Auth Method (string) */
  if ((prop_mask & 0x80) && props_len + 15 < sizeof(props)) {
    props[props_len++] = PROP_AUTH_METHOD;
    const char *methods[] = {"SCRAM-SHA-1", "PLAIN", "EXTERNAL", ""};
    const char *method = methods[xorshift32(rng) % 4];
    props_len += write_string(&props[props_len], method, strlen(method));
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

static size_t generate_connect(uint8_t *buf, size_t max_len, uint32_t *rng) {
  if (max_len < 32) return 0;

  size_t pos = 0;
  uint32_t r = xorshift32(rng);

  /*
   * Config flags byte (consumed by harness to set broker config):
   *   bit 0: retain_available - enables will message retain handling
   *   bit 1: allow_zero_length_clientid - allows empty client IDs
   *   bit 2: allow_anonymous - bypasses authentication
   *
   * Generate varied combinations to exercise both code paths for each option.
   */
  uint8_t config_flags = 0;
  uint32_t cfg_bits = xorshift32(rng);
  if (cfg_bits & 0x01) config_flags |= CFG_RETAIN_AVAILABLE;
  if (cfg_bits & 0x02) config_flags |= CFG_ALLOW_ZERO_LEN_CLIENTID;
  if (cfg_bits & 0x04) config_flags |= CFG_ALLOW_ANONYMOUS;
  buf[pos++] = config_flags;

  /* Protocol Name */
  uint8_t proto_ver;
  if ((r >> 16) % 3 == 0) {
    /* MQTT 3.1 */
    pos += write_string(&buf[pos], "MQIsdp", 6);
    proto_ver = MQTT_PROTO_31;
  } else if ((r >> 16) % 3 == 1) {
    /* MQTT 3.1.1 */
    pos += write_string(&buf[pos], "MQTT", 4);
    proto_ver = MQTT_PROTO_311;
  } else {
    /* MQTT 5.0 */
    pos += write_string(&buf[pos], "MQTT", 4);
    proto_ver = MQTT_PROTO_5;
  }

  /* Protocol Version */
  buf[pos++] = proto_ver;

  /* Connect Flags */
  uint8_t flags = 0;
  uint32_t flag_bits = xorshift32(rng);
  if (flag_bits & 0x01) flags |= FLAG_CLEAN_START;
  if (flag_bits & 0x02) flags |= FLAG_WILL;
  if (flag_bits & 0x04) flags |= FLAG_WILL_QOS1;
  if (flag_bits & 0x08) flags |= FLAG_WILL_QOS2;
  if (flag_bits & 0x10) flags |= FLAG_WILL_RETAIN;
  if (flag_bits & 0x20) flags |= FLAG_PASSWORD;
  if (flag_bits & 0x40) flags |= FLAG_USERNAME;
  /* Ensure password requires username (MQTT spec) */
  if ((flags & FLAG_PASSWORD) && !(flags & FLAG_USERNAME)) {
    flags |= FLAG_USERNAME;
  }
  buf[pos++] = flags;

  /* Keep Alive */
  uint16_t keepalive = xorshift32(rng) & 0xFFFF;
  pos += write_u16(&buf[pos], keepalive);

  /* MQTT 5.0 Properties */
  if (proto_ver == MQTT_PROTO_5) {
    pos += generate_properties(&buf[pos], max_len - pos, rng);
  }

  /* Client ID */
  char client_id[32];
  int id_len = snprintf(client_id, sizeof(client_id), "fuzz-%08x", xorshift32(rng));
  /*
   * Sometimes use empty client ID (valid in MQTT 3.1.1+ with clean session).
   * Generate empty IDs more often when allow_zero_length_clientid is set,
   * to explore both the success and error paths.
   */
  int empty_prob = (config_flags & CFG_ALLOW_ZERO_LEN_CLIENTID) ? 4 : 8;
  if ((xorshift32(rng) % empty_prob) == 0) id_len = 0;
  pos += write_string(&buf[pos], client_id, id_len);

  /* Will Properties + Topic + Payload (if FLAG_WILL) */
  if (flags & FLAG_WILL) {
    /* Will Properties (MQTT 5.0 only) */
    if (proto_ver == MQTT_PROTO_5) {
      /* Simple: just zero-length properties */
      buf[pos++] = 0;
    }

    /* Will Topic */
    const char *will_topics[] = {"will/topic", "test/will", "$SYS/will", "/", "a/b/c/d/e"};
    const char *will_topic = will_topics[xorshift32(rng) % 5];
    pos += write_string(&buf[pos], will_topic, strlen(will_topic));

    /* Will Payload */
    char will_payload[64];
    int payload_len = snprintf(will_payload, sizeof(will_payload), "will-payload-%d", xorshift32(rng) % 1000);
    pos += write_string(&buf[pos], will_payload, payload_len);
  }

  /* Username (if FLAG_USERNAME) */
  if (flags & FLAG_USERNAME) {
    const char *usernames[] = {"admin", "user", "test", "", "root", "guest"};
    const char *username = usernames[xorshift32(rng) % 6];
    pos += write_string(&buf[pos], username, strlen(username));
  }

  /* Password (if FLAG_PASSWORD) */
  if (flags & FLAG_PASSWORD) {
    const char *passwords[] = {"password", "secret", "", "12345", "\x00\x01\x02"};
    int pwd_idx = xorshift32(rng) % 5;
    const char *password = passwords[pwd_idx];
    size_t pwd_len = (pwd_idx == 4) ? 3 : strlen(password);
    pos += write_string(&buf[pos], password, pwd_len);
  }

  return pos;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  mutator_t *m = data;
  (void)buf; (void)buf_size; (void)add_buf; (void)add_buf_size;

  /* Advance RNG */
  m->seed = m->seed * 1103515245 + 12345;
  uint32_t rng = m->seed;

  /* 85% generate structured, 15% let AFL do random havoc */
  if ((rng % 100) < 85) {
    size_t len = generate_connect(m->buf, m->buf_size < max_size ? m->buf_size : max_size, &rng);
    if (len > 0) {
      *out_buf = m->buf;
      return len;
    }
  }

  /* Fall through to AFL's default mutation */
  *out_buf = NULL;
  return 0;
}

/* Post-process: occasionally corrupt the structured packet */
size_t afl_custom_post_process(void *data, uint8_t *buf, size_t buf_size,
                                uint8_t **out_buf) {
  mutator_t *m = data;
  (void)m;

  /* Pass through unchanged - let AFL's havoc stage handle corruption */
  *out_buf = buf;
  return buf_size;
}

/* Describe a test case for UI */
const char *afl_custom_describe(void *data, size_t max_len) {
  (void)data; (void)max_len;
  return "mqtt-connect";
}
