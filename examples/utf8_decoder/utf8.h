/* UTF-8 decoder example (out-of-bounds read on a truncated sequence).
 *
 * Provenance: modeled on the classic codec OOB-read bug where a multi-byte
 *   lead byte announces N bytes but the decoder reads all N continuation bytes
 *   without checking they are present within the input. This pattern underlies
 *   many real UTF-8 / charset decoder CVEs. Written from scratch.
 *
 * Bug class: out-of-bounds READ.
 * Expected finding: ASan reports a read past the end of the input buffer when a
 *   lead byte declares a 2-, 3-, or 4-byte sequence but fewer continuation
 *   bytes remain (e.g. a lone 0xF0 with len == 1).
 */
#ifndef OXFUZZ_EXAMPLE_UTF8_H
#define OXFUZZ_EXAMPLE_UTF8_H

#include <stddef.h>
#include <stdint.h>

/* Decodes the first UTF-8 code point and returns it. */
int decode_utf8(const uint8_t *data, size_t len);

#endif /* OXFUZZ_EXAMPLE_UTF8_H */
