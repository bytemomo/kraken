/*
 * Mosquitto broker CONNECT handler fuzzer
 *
 * Fuzzes the broker's CONNECT packet handler (handle__connect).
 * This is the most complex packet handler and processes:
 *   - Protocol name/version validation
 *   - Client ID parsing and validation
 *   - Will message parsing (topic, payload, QoS, retain)
 *   - Username/password authentication
 *   - MQTT 5.0 properties (session expiry, auth method, user properties)
 *
 * Input format:
 *   Entire input is the CONNECT packet payload (variable header + payload).
 *   No control bytes - protocol version is read from the packet itself.
 *
 * Security-critical because:
 *   - Parses untrusted network input
 *   - Complex state machine with many branches
 *   - Authentication/authorization decisions
 *   - Memory allocations based on attacker-controlled lengths
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto/mqtt_protocol.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"
#include "read_handle.h"

/* Input format:
 *   byte 0: config flags (fuzz-controlled to explore both enabled/disabled paths)
 *     bit 0: retain_available
 *     bit 1: allow_zero_length_clientid
 *     bit 2: allow_anonymous
 *   bytes 1+: CONNECT packet payload
 *
 * Minimum: 1-byte config + 2-byte proto len + 4-byte "MQTT" + 1-byte version + 1-byte flags + 2-byte keepalive
 */
#define MIN_INPUT_LEN 11
#define MAX_INPUT_LEN (256 * 1024)

/* Global broker database - required by broker code */
/* Note: mosquitto 2.x uses mosquitto_db, older versions used mosquitto__db */

/* Deterministic auth callback for reproducible fuzzing */
static int fuzz_basic_auth(int event, void *event_data, void *userdata) {
  (void)event;
  (void)userdata;
  struct mosquitto_evt_basic_auth *ed =
      (struct mosquitto_evt_basic_auth *)event_data;

  /* Accept/reject based on client ID to exercise both paths */
  if (ed->client->id && (ed->client->id[0] % 2 == 0)) {
    return MOSQ_ERR_SUCCESS;
  }
  return MOSQ_ERR_AUTH;
}

static int fuzz_init_context(struct mosquitto *context,
                             struct mosquitto__listener *listener,
                             struct mosquitto__security_options *secopts,
                             uint8_t config_flags) {
  memset(listener, 0, sizeof(*listener));
  memset(secopts, 0, sizeof(*secopts));

  listener->security_options = secopts;
  context->listener = listener;

  /* Fuzz-controlled listener options to explore both code paths */
  listener->max_qos = 2;
  listener->max_topic_alias = 10;

  /* Fuzz-controlled security options */
  secopts->allow_zero_length_clientid = (config_flags & 0x02) ? true : false;
  secopts->allow_anonymous = (config_flags & 0x04) ? true : false;

  /* Allocate plugin ID for auth callback */
  secopts->pid =
      (mosquitto_plugin_id_t *)calloc(1, sizeof(mosquitto_plugin_id_t));
  if (!secopts->pid)
    return 1;

  /* Initialize plugin config so callback registration works.
   * mosquitto_callback_register() requires security_option_count > 0
   * and iterates through security_options[] to register the callback. */
  secopts->pid->config.security_option_count = 1;
  secopts->pid->config.security_options =
      (struct mosquitto__security_options **)malloc(
          sizeof(struct mosquitto__security_options *));
  if (!secopts->pid->config.security_options) {
    free(secopts->pid);
    return 1;
  }
  secopts->pid->config.security_options[0] = secopts;

  mosquitto_callback_register(secopts->pid, MOSQ_EVT_BASIC_AUTH,
                              fuzz_basic_auth, NULL, NULL);

  /* Allocate bridge struct (some code paths check this) */
  context->bridge =
      (struct mosquitto__bridge *)calloc(1, sizeof(struct mosquitto__bridge));
  if (!context->bridge) {
    free(secopts->pid->config.security_options);
    free(secopts->pid);
    return 1;
  }

  return 0;
}

static void fuzz_cleanup_context(struct mosquitto *context,
                                 struct mosquitto__security_options *secopts) {
  if (secopts->pid) {
    mosquitto_callback_unregister(secopts->pid, MOSQ_EVT_BASIC_AUTH,
                                  fuzz_basic_auth, NULL);
    free(secopts->pid->config.security_options);
    free(secopts->pid);
    secopts->pid = NULL;
  }
  free(context->bridge);
  context->bridge = NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct mosquitto *context = NULL;
  struct mosquitto__listener listener;
  struct mosquitto__security_options secopts;
  uint8_t *data_heap = NULL;

  if (size < MIN_INPUT_LEN || size > MAX_INPUT_LEN) {
    return 0;
  }

  /* Extract config flags from first byte */
  uint8_t config_flags = data[0];
  data++;
  size--;

  /* Initialize global broker config */
  db.config =
      (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
  if (!db.config)
    return 0;
  log__init(db.config);

  /* Fuzz-controlled global config options */
  db.config->retain_available = (config_flags & 0x01) ? true : false;
  db.config->max_keepalive = 65535;
  db.config->message_size_limit = 256 * 1024;

  context = context__init();
  if (!context) {
    free(db.config);
    return 0;
  }

  if (fuzz_init_context(context, &listener, &secopts, config_flags)) {
    context__cleanup(context, true);
    free(db.config);
    return 0;
  }

  /* CONNECT handler requires state == mosq_cs_new, otherwise immediate rejection */
  context->state = mosq_cs_new;

  /* Protocol version is read from the packet payload itself by handle__connect().
   * The context->protocol field is only used for error message formatting.
   * We don't need to pre-set it - handle__connect() will set it correctly. */

  /* Remaining input is the CONNECT packet payload */
  data_heap = (uint8_t *)malloc(size);
  if (!data_heap) {
    fuzz_cleanup_context(context, &secopts);
    context__cleanup(context, true);
    free(db.config);
    return 0;
  }

  memcpy(data_heap, data, size);

  /* Set up packet structure for CONNECT
   * pos=0: start reading from beginning of payload
   * remaining_length=size: full payload available to read
   */
  context->in_packet.command = CMD_CONNECT;
  context->in_packet.payload = data_heap;
  context->in_packet.packet_length = (uint32_t)size;
  context->in_packet.remaining_length = (uint32_t)size;
  context->in_packet.pos = 0;

  /* FUZZ TARGET: handle__connect() */
  (void)handle__connect(context);

  /* Cleanup */
  fuzz_cleanup_context(context, &secopts);
  context__cleanup(context, true);
  free(db.config);
  memset(&db, 0, sizeof(db));

  return 0;
}

#ifndef __AFL_FUZZ_TESTCASE_LEN
/* Standalone main() for coverage builds (non-AFL/libfuzzer) */
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize <= 0 || fsize > MAX_INPUT_LEN) {
    fclose(f);
    return 0;
  }
  uint8_t *buf = malloc(fsize);
  if (!buf) {
    fclose(f);
    return 1;
  }
  if (fread(buf, 1, fsize, f) != (size_t)fsize) {
    free(buf);
    fclose(f);
    return 1;
  }
  fclose(f);
  LLVMFuzzerTestOneInput(buf, fsize);
  free(buf);
  return 0;
}
#endif
