#include "chunk.h"

#include <stdlib.h>
#include <string.h>

/* The first byte is a declared payload length. We allocate a fixed 16-byte
 * scratch buffer but copy `declared` bytes into it, trusting the header. */
int copy_chunk(const uint8_t *data, size_t len) {
    if (len < 1) {
        return 0;
    }
    size_t declared = data[0];
    size_t available = len - 1;
    size_t n = declared < available ? declared : available;

    char *buf = (char *)malloc(16);
    if (!buf) {
        return 0;
    }
    memcpy(buf, data + 1, n); /* BUG: n may exceed 16 -> heap overflow */
    int r = buf[0];
    free(buf);
    return r;
}
