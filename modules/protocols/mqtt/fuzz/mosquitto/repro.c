/*
 * Crash reproducer for mosquitto fuzzers
 *
 * Usage: ./repro <crash_file>
 *
 * Reads a crash file and replays it through the fuzzer harness
 * for debugging with ASan/UBSan but without AFL++ overhead.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Harness entry points */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s CRASH_FILE\n", argv[0]);
    return 1;
  }

  /* Initialize the harness */
  LLVMFuzzerInitialize(&argc, &argv);

  const char *path = argv[1];
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(f);
    return 1;
  }

  long sz = ftell(f);
  if (sz < 0) {
    perror("ftell");
    fclose(f);
    return 1;
  }

  if (fseek(f, 0, SEEK_SET) != 0) {
    perror("fseek");
    fclose(f);
    return 1;
  }

  uint8_t *buf = (uint8_t *)malloc((size_t)sz);
  if (!buf) {
    fprintf(stderr, "malloc failed\n");
    fclose(f);
    return 1;
  }

  size_t n = fread(buf, 1, (size_t)sz, f);
  fclose(f);

  if (n != (size_t)sz) {
    fprintf(stderr, "short read: expected %ld, got %zu\n", sz, n);
    free(buf);
    return 1;
  }

  printf("Replaying %s (%zu bytes)\n", path, n);

  /* Run the fuzzer harness */
  LLVMFuzzerTestOneInput(buf, (size_t)sz);

  free(buf);
  printf("Replay complete\n");
  return 0;
}
