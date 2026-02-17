/*
 * Mosquitto broker PUBLISH handler fuzzer
 *
 * Fuzzes the broker's PUBLISH packet handler (handle__publish).
 * PUBLISH packets are the most common packet type and process:
 *   - Topic name parsing and validation
 *   - Topic ACL checks
 *   - QoS handling (0, 1, 2)
 *   - Retain flag processing
 *   - MQTT 5.0 properties (topic alias, message expiry, content type, etc.)
 *   - Payload handling
 *
 * Input format:
 *   byte 0: config flags (fuzz-controlled)
 *     bit 0: retain_available
 *   byte 1: QoS/retain/dup flags
 *   byte 2: protocol version selector
 *   bytes 3+: PUBLISH packet payload
 *
 * Security-critical because:
 *   - Topic validation is complex (wildcards, special prefixes)
 *   - ACL bypass potential
 *   - Topic alias can cause memory issues
 *   - Large payloads stress memory handling
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto/mqtt_protocol.h"
#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"
#include "read_handle.h"

#define MIN_INPUT_LEN 4
#define MAX_INPUT_LEN (256 * 1024)

/* Note: mosquitto 2.x uses mosquitto_db, older versions used mosquitto__db */

/* ACL callback - allows based on topic first char for path exploration */
static int fuzz_acl_check(int event, void *event_data, void *userdata) {
  (void)event;
  (void)userdata;
  struct mosquitto_evt_acl_check *ed =
      (struct mosquitto_evt_acl_check *)event_data;

  if (ed->topic && ed->topic[0] && (ed->topic[0] % 3 == 0)) {
    return MOSQ_ERR_SUCCESS;
  }
  return MOSQ_ERR_ACL_DENIED;
}

static int fuzz_init_context(struct mosquitto *context,
                             struct mosquitto__listener *listener,
                             struct mosquitto__security_options *secopts) {
  memset(listener, 0, sizeof(*listener));
  memset(secopts, 0, sizeof(*secopts));

  listener->security_options = secopts;
  listener->max_qos = 2;
  listener->max_topic_alias = 10;
  context->listener = listener;

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

  mosquitto_callback_register(secopts->pid, MOSQ_EVT_ACL_CHECK, fuzz_acl_check,
                              NULL, NULL);

  context->bridge =
      (struct mosquitto__bridge *)calloc(1, sizeof(struct mosquitto__bridge));
  if (!context->bridge) {
    free(secopts->pid->config.security_options);
    free(secopts->pid);
    return 1;
  }

  /* Pre-authenticate the context for PUBLISH handling */
  context->id = strdup("fuzz-client");
  if (!context->id) {
    free(context->bridge);
    free(secopts->pid->config.security_options);
    free(secopts->pid);
    return 1;
  }

  return 0;
}

static void fuzz_cleanup_context(struct mosquitto *context,
                                 struct mosquitto__security_options *secopts) {
  if (secopts->pid) {
    mosquitto_callback_unregister(secopts->pid, MOSQ_EVT_ACL_CHECK,
                                  fuzz_acl_check, NULL);
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

  db.config =
      (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
  if (!db.config)
    return 0;
  log__init(db.config);

  /* Fuzz-controlled global config options */
  db.config->retain_available = (config_flags & 0x01) ? true : false;
  db.config->message_size_limit = 256 * 1024;

  context = context__init();
  if (!context) {
    free(db.config);
    return 0;
  }

  if (fuzz_init_context(context, &listener, &secopts)) {
    context__cleanup(context, true);
    free(db.config);
    return 0;
  }

  /* Derive QoS and other flags from second byte */
  uint8_t qos = (data[1] >> 1) & 0x03;
  if (qos == 3)
    qos = 0; /* Invalid QoS, use 0 */
  uint8_t retain = data[1] & 0x01;
  uint8_t dup = (data[1] >> 3) & 0x01;

  /* Set client state to connected/active */
  context->state = mosq_cs_active;

  /* Protocol selection from third byte */
  if (data[2] < 128) {
    context->protocol = mosq_p_mqtt311;
  } else {
    context->protocol = mosq_p_mqtt5;
  }

  size -= 3;
  data_heap = (uint8_t *)malloc(size + 1);
  if (!data_heap) {
    fuzz_cleanup_context(context, &secopts);
    context__cleanup(context, true);
    free(db.config);
    return 0;
  }

  memcpy(data_heap, &data[3], size);

  /* Set up PUBLISH packet */
  uint8_t cmd = CMD_PUBLISH | (qos << 1) | retain | (dup << 3);
  context->in_packet.command = cmd;
  context->in_packet.payload = data_heap;
  context->in_packet.packet_length = (uint32_t)size;
  context->in_packet.remaining_length = (uint32_t)size;
  context->in_packet.pos = 0;

  /* FUZZ TARGET: handle__publish() */
  (void)handle__publish(context);

  fuzz_cleanup_context(context, &secopts);
  context__cleanup(context, true);
  free(db.config);
  memset(&db, 0, sizeof(db));

  return 0;
}

#ifndef __AFL_FUZZ_TESTCASE_LEN
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
