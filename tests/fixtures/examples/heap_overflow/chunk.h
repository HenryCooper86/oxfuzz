/* Heap-buffer-overflow (write) example.
 *
 * Provenance: the archetypal "trust the length field" bug behind countless
 * media/codec CVEs -- a header advertises a size, code allocates one fixed
 * buffer, then copies the attacker-controlled amount into it.
 *
 * Bug class: heap-buffer-overflow (WRITE).
 * Expected finding: ASan reports a heap write past the end of a 16-byte buffer
 *   whenever the declared payload length exceeds 16.
 */
#ifndef HF_EXAMPLE_CHUNK_H
#define HF_EXAMPLE_CHUNK_H

#include <stddef.h>
#include <stdint.h>

/* Parses [len:1][payload...] and copies the payload into a fixed buffer. */
int copy_chunk(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_CHUNK_H */
