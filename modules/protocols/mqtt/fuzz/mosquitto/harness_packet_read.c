/*
 * Mosquitto client-side packet read fuzzer
 *
 * Fuzzes the client library's packet parsing code via packet__read().
 * This tests the MQTT packet parsing primitives used by the client library.
 *
 * Input format: raw MQTT packet data
 * The fuzzer creates a socket pair and feeds the fuzz input to the mosquitto
 * client's packet reader.
 *
 * Target functions:
 *   - packet__read() - Main packet read dispatcher
 *   - packet__read_byte/uint16/uint32/varint() - Primitive readers
 *   - packet__read_string/binary() - String/binary data readers
 *   - handle_* functions for each packet type
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "packet_mosq.h"
#include "read_handle.h"

static int g_initialized = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
    return 0;
  }
  g_initialized = 1;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!g_initialized)
    return 0;

  /* Need at least 2 bytes for a minimal MQTT fixed header */
  if (size < 2 || size > (1 << 20))
    return 0;

  struct mosquitto *mosq = mosquitto_new(NULL, true, NULL);
  if (!mosq)
    return 0;

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
    mosquitto_destroy(mosq);
    return 0;
  }

  /* Set non-blocking to avoid hangs */
  fcntl(sv[0], F_SETFL, O_NONBLOCK);

  ssize_t written = write(sv[1], data, size);
  if (written < (ssize_t)size) {
    close(sv[0]);
    close(sv[1]);
    mosquitto_destroy(mosq);
    return 0;
  }

  /* Signal EOF to the reader */
  close(sv[1]);

  mosq->sock = sv[0];

  /* Test both MQTT 3.1.1 and MQTT 5 protocols based on first byte */
  if (data[0] & 0x01) {
    mosq->protocol = mosq_p_mqtt5;
  } else {
    mosq->protocol = mosq_p_mqtt311;
  }
  mosq->state = mosq_cs_connected;

  /* Call the packet reader - this is the main fuzzing target */
  (void)packet__read(mosq);

  /* Prevent double-close */
  mosq->sock = -1;
  close(sv[0]);
  mosquitto_destroy(mosq);

  return 0;
}
