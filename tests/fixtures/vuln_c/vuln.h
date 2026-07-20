/* Deliberately vulnerable functions for verifying that the fuzzer + ASan
 * actually catch bugs. Each takes a (data, len) byte buffer so oxfuzz's
 * discovery + heuristic harness generation pick them up directly.
 *
 * DO NOT use this code for anything but fuzzing-pipeline tests. */
#ifndef OXFUZZ_VULN_H
#define OXFUZZ_VULN_H

#include <stddef.h>
#include <stdint.h>

/* Heap-buffer-overflow: copies len bytes into a 4-byte heap allocation. */
int parse_record(const uint8_t *data, size_t len);

/* Use-after-free: reads a freed buffer when the input starts with 'U'. */
int parse_tag(const uint8_t *data, size_t len);

/* Stack-buffer-overflow: copies len bytes onto an 8-byte stack buffer. */
int parse_frame(const uint8_t *data, size_t len);

#endif /* OXFUZZ_VULN_H */
