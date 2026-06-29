/* Integer-truncation-leads-to-undersized-allocation example.
 *
 * Provenance: the width x height allocation bug behind many image-decoder CVEs
 * (libpng/libjpeg/giflib family). The pixel count is computed correctly but
 * truncated into a narrow type when sizing the allocation, so malloc returns a
 * tiny buffer while the decode loop writes the full pixel count.
 *
 * Bug class: integer truncation (CWE-681) -> heap-buffer-overflow (WRITE).
 * Expected finding: ASan reports a heap overflow when width * height exceeds
 *   65535 (e.g. width = height = 0x0100), because the 16-bit allocation size
 *   wraps to a small value while the loop still writes width * height bytes.
 */
#ifndef HF_EXAMPLE_PIXELS_H
#define HF_EXAMPLE_PIXELS_H

#include <stddef.h>
#include <stdint.h>

/* Parses a [width:2][height:2] header and "decodes" width*height pixels. */
int parse_image(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_PIXELS_H */
