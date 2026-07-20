/* Deliberately vulnerable functions -- see vuln.h. Each bug is reachable from
 * a (data, len) entry point so AddressSanitizer flags it within milliseconds
 * of fuzzing. Used to verify oxfuzz's discover -> harness -> run -> triage
 * pipeline actually finds bugs. */
#include "vuln.h"

#include <stdlib.h>
#include <string.h>

/* Heap-buffer-overflow: a 4-byte heap buffer is overrun whenever len > 4. */
int parse_record(const uint8_t *data, size_t len) {
    char *buf = (char *)malloc(4);
    if (!buf) {
        return 0;
    }
    memcpy(buf, data, len); /* BUG: writes len bytes into a 4-byte buffer */
    int r = buf[0];
    free(buf);
    return r;
}

/* Use-after-free: the buffer is read after free() when the first byte is 'U'. */
int parse_tag(const uint8_t *data, size_t len) {
    if (len == 0) {
        return 0;
    }
    char *buf = (char *)malloc(16);
    if (!buf) {
        return 0;
    }
    size_t n = len < 16 ? len : 16;
    memcpy(buf, data, n);
    free(buf);
    if (data[0] == 'U') {
        return buf[0]; /* BUG: read of freed memory */
    }
    return 0;
}

/* Stack-buffer-overflow: an 8-byte stack buffer is overrun whenever len > 8. */
int parse_frame(const uint8_t *data, size_t len) {
    char buf[8];
    memcpy(buf, data, len); /* BUG: writes len bytes onto an 8-byte stack buffer */
    return buf[len % 8];
}
