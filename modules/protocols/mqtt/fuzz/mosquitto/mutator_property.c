/*
 * AFL++ Custom Mutator for MQTT 5.0 Properties
 *
 * Generates structurally valid property blocks to reach deeper parsing paths.
 * Understands all MQTT 5.0 property types and their encodings.
 *
 * Build: clang -shared -fPIC -O2 -Wall mutator_property.c -o mutator_property.so
 * Usage: AFL_CUSTOM_MUTATOR_LIBRARY=./mutator_property.so afl-fuzz ...
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t *buf;
  size_t buf_size;
  uint32_t seed;
} mutator_t;

/* MQTT 5.0 Property Identifiers */
#define PROP_PAYLOAD_FORMAT           0x01  /* Byte */
#define PROP_MESSAGE_EXPIRY           0x02  /* 4-byte int */
#define PROP_CONTENT_TYPE             0x03  /* UTF-8 string */
#define PROP_RESPONSE_TOPIC           0x08  /* UTF-8 string */
#define PROP_CORRELATION_DATA         0x09  /* Binary */
#define PROP_SUBSCRIPTION_ID          0x0B  /* Varint */
#define PROP_SESSION_EXPIRY           0x11  /* 4-byte int */
#define PROP_ASSIGNED_CLIENT_ID       0x12  /* UTF-8 string */
#define PROP_SERVER_KEEPALIVE         0x13  /* 2-byte int */
#define PROP_AUTH_METHOD              0x15  /* UTF-8 string */
#define PROP_AUTH_DATA                0x16  /* Binary */
#define PROP_REQUEST_PROBLEM          0x17  /* Byte */
#define PROP_WILL_DELAY               0x18  /* 4-byte int */
#define PROP_REQUEST_RESPONSE         0x19  /* Byte */
#define PROP_RESPONSE_INFO            0x1A  /* UTF-8 string */
#define PROP_SERVER_REFERENCE         0x1C  /* UTF-8 string */
#define PROP_REASON_STRING            0x1F  /* UTF-8 string */
#define PROP_RECEIVE_MAX              0x21  /* 2-byte int */
#define PROP_TOPIC_ALIAS_MAX          0x22  /* 2-byte int */
#define PROP_TOPIC_ALIAS              0x23  /* 2-byte int */
#define PROP_MAX_QOS                  0x24  /* Byte */
#define PROP_RETAIN_AVAILABLE         0x25  /* Byte */
#define PROP_USER_PROPERTY            0x26  /* String pair */
#define PROP_MAX_PACKET_SIZE          0x27  /* 4-byte int */
#define PROP_WILDCARD_SUB_AVAIL       0x28  /* Byte */
#define PROP_SUB_ID_AVAILABLE         0x29  /* Byte */
#define PROP_SHARED_SUB_AVAIL         0x2A  /* Byte */

/* Command types for context selection */
#define CMD_CONNECT     0x10
#define CMD_CONNACK     0x20
#define CMD_PUBLISH     0x30
#define CMD_PUBACK      0x40
#define CMD_SUBSCRIBE   0x82
#define CMD_SUBACK      0x90
#define CMD_UNSUBSCRIBE 0xA2
#define CMD_DISCONNECT  0xE0
#define CMD_AUTH        0xF0
#define CMD_WILL        0x00  /* Special: will properties */

/* Property type encoding */
typedef enum {
  PROP_TYPE_BYTE,
  PROP_TYPE_U16,
  PROP_TYPE_U32,
  PROP_TYPE_VARINT,
  PROP_TYPE_STRING,
  PROP_TYPE_BINARY,
  PROP_TYPE_STRING_PAIR
} prop_type_t;

typedef struct {
  uint8_t id;
  prop_type_t type;
} prop_def_t;

static const prop_def_t all_properties[] = {
  { PROP_PAYLOAD_FORMAT,      PROP_TYPE_BYTE },
  { PROP_MESSAGE_EXPIRY,      PROP_TYPE_U32 },
  { PROP_CONTENT_TYPE,        PROP_TYPE_STRING },
  { PROP_RESPONSE_TOPIC,      PROP_TYPE_STRING },
  { PROP_CORRELATION_DATA,    PROP_TYPE_BINARY },
  { PROP_SUBSCRIPTION_ID,     PROP_TYPE_VARINT },
  { PROP_SESSION_EXPIRY,      PROP_TYPE_U32 },
  { PROP_ASSIGNED_CLIENT_ID,  PROP_TYPE_STRING },
  { PROP_SERVER_KEEPALIVE,    PROP_TYPE_U16 },
  { PROP_AUTH_METHOD,         PROP_TYPE_STRING },
  { PROP_AUTH_DATA,           PROP_TYPE_BINARY },
  { PROP_REQUEST_PROBLEM,     PROP_TYPE_BYTE },
  { PROP_WILL_DELAY,          PROP_TYPE_U32 },
  { PROP_REQUEST_RESPONSE,    PROP_TYPE_BYTE },
  { PROP_RESPONSE_INFO,       PROP_TYPE_STRING },
  { PROP_SERVER_REFERENCE,    PROP_TYPE_STRING },
  { PROP_REASON_STRING,       PROP_TYPE_STRING },
  { PROP_RECEIVE_MAX,         PROP_TYPE_U16 },
  { PROP_TOPIC_ALIAS_MAX,     PROP_TYPE_U16 },
  { PROP_TOPIC_ALIAS,         PROP_TYPE_U16 },
  { PROP_MAX_QOS,             PROP_TYPE_BYTE },
  { PROP_RETAIN_AVAILABLE,    PROP_TYPE_BYTE },
  { PROP_USER_PROPERTY,       PROP_TYPE_STRING_PAIR },
  { PROP_MAX_PACKET_SIZE,     PROP_TYPE_U32 },
  { PROP_WILDCARD_SUB_AVAIL,  PROP_TYPE_BYTE },
  { PROP_SUB_ID_AVAILABLE,    PROP_TYPE_BYTE },
  { PROP_SHARED_SUB_AVAIL,    PROP_TYPE_BYTE },
};
#define NUM_PROPERTIES (sizeof(all_properties) / sizeof(all_properties[0]))

static uint32_t xorshift32(uint32_t *state) {
  uint32_t x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
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

static size_t write_u16(uint8_t *buf, uint16_t val) {
  buf[0] = (val >> 8) & 0xFF;
  buf[1] = val & 0xFF;
  return 2;
}

static size_t write_u32(uint8_t *buf, uint32_t val) {
  buf[0] = (val >> 24) & 0xFF;
  buf[1] = (val >> 16) & 0xFF;
  buf[2] = (val >> 8) & 0xFF;
  buf[3] = val & 0xFF;
  return 4;
}

static size_t write_string(uint8_t *buf, const char *str, size_t len) {
  write_u16(buf, (uint16_t)len);
  if (len > 0) memcpy(buf + 2, str, len);
  return 2 + len;
}

static size_t write_binary(uint8_t *buf, const uint8_t *data, size_t len) {
  write_u16(buf, (uint16_t)len);
  if (len > 0) memcpy(buf + 2, data, len);
  return 2 + len;
}

/* Generate a single property */
static size_t generate_property(uint8_t *buf, size_t max_len,
                                const prop_def_t *prop, uint32_t *rng) {
  if (max_len < 10) return 0;

  size_t pos = 0;

  /* Property identifier (varint, but all current IDs fit in 1 byte) */
  pos += write_varint(&buf[pos], prop->id);

  switch (prop->type) {
    case PROP_TYPE_BYTE:
      buf[pos++] = xorshift32(rng) & 0xFF;
      break;

    case PROP_TYPE_U16:
      pos += write_u16(&buf[pos], xorshift32(rng) & 0xFFFF);
      break;

    case PROP_TYPE_U32:
      pos += write_u32(&buf[pos], xorshift32(rng));
      break;

    case PROP_TYPE_VARINT: {
      /* Generate varints of different sizes */
      uint32_t val;
      switch (xorshift32(rng) % 4) {
        case 0: val = xorshift32(rng) & 0x7F; break;          /* 1 byte */
        case 1: val = xorshift32(rng) & 0x3FFF; break;        /* 2 bytes */
        case 2: val = xorshift32(rng) & 0x1FFFFF; break;      /* 3 bytes */
        default: val = xorshift32(rng) & 0x0FFFFFFF; break;   /* 4 bytes */
      }
      pos += write_varint(&buf[pos], val);
      break;
    }

    case PROP_TYPE_STRING: {
      const char *strings[] = {
        "", "a", "test", "application/json", "text/plain",
        "very-long-content-type-string-for-testing-purposes",
        "\x00\x01\x02",  /* Invalid UTF-8 */
        "utf8-valid-\xC3\xA9\xC3\xA0",  /* Valid UTF-8 */
        "$SYS/broker/version",
        "response/topic/with/many/levels/a/b/c/d/e/f"
      };
      int idx = xorshift32(rng) % 10;
      const char *s = strings[idx];
      size_t slen = (idx == 2) ? 3 : strlen(s);  /* Handle embedded null */
      if (pos + 2 + slen > max_len) return 0;
      pos += write_string(&buf[pos], s, slen);
      break;
    }

    case PROP_TYPE_BINARY: {
      /* Generate binary data of various sizes */
      size_t blen = xorshift32(rng) % 64;
      if (pos + 2 + blen > max_len) return 0;
      write_u16(&buf[pos], (uint16_t)blen);
      pos += 2;
      for (size_t i = 0; i < blen; i++) {
        buf[pos++] = xorshift32(rng) & 0xFF;
      }
      break;
    }

    case PROP_TYPE_STRING_PAIR: {
      const char *keys[] = {"key", "user", "x-custom", "", "name"};
      const char *vals[] = {"value", "data", "", "test", "long-value-string"};
      int kidx = xorshift32(rng) % 5;
      int vidx = xorshift32(rng) % 5;
      const char *k = keys[kidx];
      const char *v = vals[vidx];
      if (pos + 4 + strlen(k) + strlen(v) > max_len) return 0;
      pos += write_string(&buf[pos], k, strlen(k));
      pos += write_string(&buf[pos], v, strlen(v));
      break;
    }
  }

  return pos;
}

/* Generate a complete property block with length prefix */
static size_t generate_properties(uint8_t *buf, size_t max_len, uint32_t *rng) {
  if (max_len < 16) return 0;

  uint8_t props[2048];
  size_t props_len = 0;

  /* Generate 0-10 properties */
  int num_props = xorshift32(rng) % 11;

  for (int i = 0; i < num_props && props_len < sizeof(props) - 100; i++) {
    /* Pick a random property */
    int prop_idx = xorshift32(rng) % NUM_PROPERTIES;
    size_t plen = generate_property(&props[props_len],
                                    sizeof(props) - props_len,
                                    &all_properties[prop_idx], rng);
    props_len += plen;
  }

  /* Sometimes generate duplicate properties (should be rejected) */
  if ((xorshift32(rng) % 10) == 0 && props_len > 0 && props_len < sizeof(props) - 100) {
    int prop_idx = xorshift32(rng) % NUM_PROPERTIES;
    props_len += generate_property(&props[props_len],
                                   sizeof(props) - props_len,
                                   &all_properties[prop_idx], rng);
  }

  /* Write varint length prefix */
  size_t hdr_len = write_varint(buf, (uint32_t)props_len);
  if (hdr_len + props_len > max_len) {
    /* Just return empty properties */
    buf[0] = 0;
    return 1;
  }

  memcpy(buf + hdr_len, props, props_len);
  return hdr_len + props_len;
}

static size_t generate_input(uint8_t *buf, size_t max_len, uint32_t *rng) {
  if (max_len < 8) return 0;

  size_t pos = 0;

  /* Byte 0: command selector (harness uses data[0] % 10) */
  buf[pos++] = xorshift32(rng) % 10;

  /* Generate property block */
  pos += generate_properties(&buf[pos], max_len - pos, rng);

  return pos;
}

void *afl_custom_init(void *afl, unsigned int seed) {
  (void)afl;
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

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  mutator_t *m = data;
  (void)buf; (void)buf_size; (void)add_buf; (void)add_buf_size;

  /* Advance RNG */
  m->seed = m->seed * 1103515245 + 12345;
  uint32_t rng = m->seed;

  /* 75% generate structured, 25% let AFL do random havoc */
  if ((rng % 100) < 75) {
    size_t len = generate_input(m->buf,
                                m->buf_size < max_size ? m->buf_size : max_size,
                                &rng);
    if (len > 0) {
      *out_buf = m->buf;
      return len;
    }
  }

  /* Fall through to AFL's default mutation */
  *out_buf = NULL;
  return 0;
}

const char *afl_custom_describe(void *data, size_t max_len) {
  (void)data; (void)max_len;
  return "mqtt5-property";
}
