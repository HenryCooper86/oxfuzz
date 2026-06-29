/* Out-of-bounds read from a length-prefixed chunk (PNG/TIFF-style).
 *
 * Provenance: chunked container formats (PNG `IDAT`, TIFF tags, RIFF) where a
 * length field is trusted and the reader walks that many bytes past the header
 * without checking it against the bytes actually present. The historical
 * libpng/libtiff over-read CVEs follow this shape.
 *
 * Bug class: heap-buffer-overflow (READ).
 * Expected finding: ASan reports an out-of-bounds read when the declared chunk
 *   length is larger than the remaining input (e.g. length byte 0xFF with only
 *   a few trailing bytes), as the checksum loop walks off the end.
 */
#ifndef HF_EXAMPLE_CHUNK_READER_H
#define HF_EXAMPLE_CHUNK_READER_H

#include <stddef.h>
#include <stdint.h>

/* Parses [length:1][payload...] and checksums `length` payload bytes. */
int read_chunk(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_CHUNK_READER_H */
