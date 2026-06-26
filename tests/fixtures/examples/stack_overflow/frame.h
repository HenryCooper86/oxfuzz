/* Stack-buffer-overflow example.
 *
 * Provenance: fixed-size on-stack scratch buffers filled from a length-prefixed
 * record -- a recurring pattern in binary format parsers.
 *
 * Bug class: stack-buffer-overflow (WRITE).
 * Expected finding: ASan reports a stack write past an 8-byte buffer whenever
 *   the declared frame length exceeds 8.
 */
#ifndef HF_EXAMPLE_FRAME_H
#define HF_EXAMPLE_FRAME_H

#include <stddef.h>
#include <stdint.h>

/* Parses [len:1][payload...] into a fixed on-stack buffer. */
int unpack_frame(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_FRAME_H */
