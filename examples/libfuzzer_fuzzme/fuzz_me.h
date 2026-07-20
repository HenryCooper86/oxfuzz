/* libFuzzer canonical "FuzzMe" example.
 *
 * Provenance: modeled on google/fuzzing tutorial/libFuzzer/fuzz_me.cc and the
 *   LLVM libFuzzer documentation (Apache-2.0). Written from scratch, not copied.
 *   This is THE textbook libFuzzer target.
 *
 * Bug class: heap-buffer-overflow (READ).
 * Expected finding: AddressSanitizer reports a 1-byte out-of-bounds read of
 *   data[3] for any heap input whose first three bytes are 'F','U','Z' but
 *   whose length is exactly 3 (so data[3] is past the end of the allocation).
 */
#ifndef OXFUZZ_EXAMPLE_FUZZ_ME_H
#define OXFUZZ_EXAMPLE_FUZZ_ME_H

#include <stddef.h>
#include <stdint.h>

/* Returns non-zero when the input spells "FUZZ". */
int FuzzMe(const uint8_t *data, size_t size);

#endif /* OXFUZZ_EXAMPLE_FUZZ_ME_H */
