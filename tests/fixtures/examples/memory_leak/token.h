/* Memory-leak example (LeakSanitizer).
 *
 * Provenance: the early-return-without-free bug -- a parser allocates, hits a
 * validation error on some inputs, and returns without releasing the buffer.
 * LeakSanitizer (bundled with ASan) reports the leaked allocation at exit.
 *
 * Bug class: memory leak.
 * Expected finding: LeakSanitizer reports a leaked heap allocation when the
 *   input takes the error path (a token longer than the 4-byte limit).
 */
#ifndef HF_EXAMPLE_TOKEN_H
#define HF_EXAMPLE_TOKEN_H

#include <stddef.h>
#include <stdint.h>

/* Copies a length-prefixed token, validating its length after allocating. */
int parse_token(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_TOKEN_H */
