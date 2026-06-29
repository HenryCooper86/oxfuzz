#include "pixels.h"

#include <stdlib.h>

/* width and height are read as 16-bit fields. Their product is computed in
 * full 32-bit width, but the allocation size is truncated into a 16-bit type --
 * so an area of, say, 0x10000 wraps to 0 and malloc hands back a tiny buffer
 * while the decode loop still writes the full `area` bytes. */
int parse_image(const uint8_t *data, size_t len) {
    if (len < 4) {
        return 0;
    }
    uint32_t width = (uint32_t)data[0] << 8 | (uint32_t)data[1];
    uint32_t height = (uint32_t)data[2] << 8 | (uint32_t)data[3];
    uint32_t area = width * height;

    uint16_t alloc_size = (uint16_t)area; /* BUG: truncates the real size */
    uint8_t *pixels = (uint8_t *)malloc(alloc_size);
    if (!pixels) {
        return 0;
    }
    for (uint32_t i = 0; i < area; i++) {
        pixels[i] = (uint8_t)i; /* writes `area` bytes into a truncated buffer */
    }
    int r = pixels[0];
    free(pixels);
    return r;
}
