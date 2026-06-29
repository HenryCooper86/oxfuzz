#include "chunk_reader.h"

/* The first byte is a declared chunk length. The checksum loop trusts it and
 * reads `declared` payload bytes -- but never verifies that many bytes are
 * actually present, so it walks past the end of the input buffer. */
int read_chunk(const uint8_t *data, size_t len) {
    if (len < 1) {
        return 0;
    }
    size_t declared = data[0];
    const uint8_t *payload = data + 1;

    uint32_t crc = 0;
    for (size_t i = 0; i < declared; i++) {
        crc = (crc << 1) ^ payload[i]; /* BUG: i may exceed (len - 1) */
    }
    return (int)crc;
}
