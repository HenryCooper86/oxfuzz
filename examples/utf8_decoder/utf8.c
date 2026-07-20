#include "utf8.h"

/* Number of bytes in the UTF-8 sequence introduced by lead byte `b`. */
static size_t sequence_len(uint8_t b) {
    if (b < 0x80) {
        return 1;
    }
    if ((b & 0xE0) == 0xC0) {
        return 2;
    }
    if ((b & 0xF0) == 0xE0) {
        return 3;
    }
    if ((b & 0xF8) == 0xF0) {
        return 4;
    }
    return 1;
}

/* Decodes the first code point. The continuation loop trusts the length the
 * lead byte declared and never re-checks it against `len`, so a truncated
 * multi-byte sequence walks off the end of the buffer. */
int decode_utf8(const uint8_t *data, size_t len) {
    if (len < 1) {
        return 0;
    }
    size_t n = sequence_len(data[0]);
    uint32_t cp = data[0] & (0x7Fu >> n);

    for (size_t i = 1; i < n; i++) {
        cp = (cp << 6) | (data[i] & 0x3Fu); /* BUG: i may reach past len for a truncated sequence */
    }
    return (int)cp;
}
