/* libFuzzer canonical "FuzzMe" example.
 *
 * Provenance: LLVM libFuzzer documentation and the google/fuzzing tutorial
 * (tutorial/libFuzzer/fuzz_me.cc). This is THE textbook libFuzzer target.
 *
 * Bug class: heap-buffer-overflow (READ).
 * Expected finding: AddressSanitizer reports a 1-byte out-of-bounds read of
 *   Data[3] for any heap input whose first three bytes are 'F','U','Z' but
 *   whose length is exactly 3 (so Data[3] is past the end of the allocation).
 */
#ifndef HF_EXAMPLE_FUZZ_ME_H
#define HF_EXAMPLE_FUZZ_ME_H

#include <stddef.h>
#include <stdint.h>

/* Returns non-zero when the input spells "FUZZ". */
int FuzzMe(const uint8_t *data, size_t size);

#endif /* HF_EXAMPLE_FUZZ_ME_H */
