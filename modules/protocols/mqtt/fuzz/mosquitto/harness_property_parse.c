/*
 * Mosquitto MQTT 5.0 property parsing fuzzer
 *
 * Fuzzes the MQTT 5.0 property parsing code (property__read_all).
 * MQTT 5.0 properties are a complex feature that adds significant attack
 * surface:
 *   - Variable-length integer encoding for property length
 *   - Multiple property types (byte, uint16, uint32, varint, string, binary,
 * string pair)
 *   - Property identifier validation
 *   - Duplicate property detection
 *   - Context-specific property validation
 *
 * Input format:
 *   byte 0: command type selector (affects which properties are valid)
 *   bytes 1+: raw property data (varint length + properties)
 *
 * Security-critical because:
 *   - Complex parsing logic with many branches
 *   - Memory allocation based on attacker-controlled lengths
 *   - String/binary data copied from untrusted input
 *   - Varint decoding edge cases
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"
#include "mosquitto/mqtt_protocol.h"
#include "mosquitto_internal.h"
#include "packet_mosq.h"
#include "property_mosq.h"

#define MIN_INPUT_LEN 2
#define MAX_INPUT_LEN (64 * 1024)

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
  struct mosquitto__packet_in packet;
  mosquitto_property *properties = NULL;
  int cmd;

  if (!g_initialized)
    return 0;
  if (size < MIN_INPUT_LEN || size > MAX_INPUT_LEN)
    return 0;

  /* Select command type based on first byte to test different property contexts
   */
  switch (data[0] % 10) {
  case 0:
    cmd = CMD_CONNECT;
    break;
  case 1:
    cmd = CMD_CONNACK;
    break;
  case 2:
    cmd = CMD_PUBLISH;
    break;
  case 3:
    cmd = CMD_PUBACK;
    break;
  case 4:
    cmd = CMD_SUBSCRIBE;
    break;
  case 5:
    cmd = CMD_SUBACK;
    break;
  case 6:
    cmd = CMD_UNSUBSCRIBE;
    break;
  case 7:
    cmd = CMD_DISCONNECT;
    break;
  case 8:
    cmd = CMD_AUTH;
    break;
  default:
    cmd = CMD_WILL;
    break; /* Will properties */
  }

  /* Set up packet structure for property parsing */
  memset(&packet, 0, sizeof(packet));

  /* Skip the command byte, use rest as property data */
  size_t prop_size = size - 1;
  uint8_t *prop_data = (uint8_t *)malloc(prop_size);
  if (!prop_data)
    return 0;

  memcpy(prop_data, &data[1], prop_size);

  packet.payload = prop_data;
  packet.packet_length = (uint32_t)prop_size;
  packet.remaining_length = (uint32_t)prop_size;
  packet.pos = 0;

  /* FUZZ TARGET: property__read_all()
   * This function:
   *   1. Reads varint for total property length
   *   2. Loops reading individual properties
   *   3. Each property: varint identifier + type-specific data
   *   4. Validates properties are valid for the command type
   */
  (void)property__read_all(cmd, &packet, &properties);

  /* Always free properties if allocated (even on parse failure, partial
   * results may have been allocated before the error occurred)
   */
  if (properties) {
    mosquitto_property_free_all(&properties);
  }

  free(prop_data);
  return 0;
}

#ifndef __AFL_FUZZ_TESTCASE_LEN
#include <stdio.h>
int main(int argc, char **argv) {
  LLVMFuzzerInitialize(&argc, &argv);
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
