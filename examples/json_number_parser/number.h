/* JSON numeric-token parser example (multi-function, static helpers).
 *
 * Provenance: general parser-fuzzing pattern -- a hand-written tokenizer that
 *   copies a variable-length token into a fixed on-stack scratch buffer, the
 *   classic shape behind many stack-smash CVEs in config/format parsers.
 *   Written from scratch; not derived from any single upstream file.
 *
 * Bug class: stack-buffer-overflow (WRITE).
 * Expected finding: ASan reports a stack write past the end of a 32-byte buffer
 *   whenever the leading numeric literal is longer than 32 bytes (e.g. a run of
 *   33 or more digits).
 */
#ifndef OXFUZZ_EXAMPLE_NUMBER_H
#define OXFUZZ_EXAMPLE_NUMBER_H

#include <stddef.h>
#include <stdint.h>

/* Parses the leading JSON number token and returns its accumulated value. */
int parse_number(const uint8_t *data, size_t len);

#endif /* OXFUZZ_EXAMPLE_NUMBER_H */
