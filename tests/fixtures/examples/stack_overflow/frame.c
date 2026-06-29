#include "frame.h"

#include <string.h>

/* The declared length (first byte) is copied onto an 8-byte stack buffer with
 * no bound check against the buffer's capacity. */
int unpack_frame(const uint8_t *data, size_t len) {
    if (len < 1) {
        return 0;
    }
    size_t declared = data[0];
    size_t available = len - 1;
    size_t n = declared < available ? declared : available;

    char buf[8];
    memcpy(buf, data + 1, n); /* BUG: n may exceed sizeof(buf) */
    return buf[n % 8];
}
