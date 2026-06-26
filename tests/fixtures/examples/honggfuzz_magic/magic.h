/* honggfuzz canonical "magic bytes" example.
 *
 * Provenance: honggfuzz README and honggfuzz/examples -- the introductory
 * target that crashes when the input begins with a fixed magic sequence.
 *
 * Bug class: reachable abort() / SIGABRT (assertion-style logic bug).
 * Expected finding: the fuzzer reproduces a crash on any input beginning with
 *   the bytes "ABCD". honggfuzz/AFL++/libFuzzer all converge on it quickly
 *   because each matched byte opens a new coverage edge.
 */
#ifndef HF_EXAMPLE_MAGIC_H
#define HF_EXAMPLE_MAGIC_H

#include <stddef.h>
#include <stdint.h>

/* Aborts when `data` starts with the magic bytes "ABCD". */
int match_magic(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_MAGIC_H */
