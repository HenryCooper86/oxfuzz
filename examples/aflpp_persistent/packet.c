#include "packet.h"

#include <stdlib.h>
#include <string.h>

/* A length-prefixed "packet": [type:1][declared_len:1][payload...]. The output
 * buffer is sized from the real number of remaining bytes, but the copy trusts
 * the declared length field in the header. When AFL++ drives this in persistent
 * mode it calls the same libFuzzer-compatible entry once per fuzzed input. */
int parse_packet(const uint8_t *data, size_t len) {
    if (len < 2) {
        return 0;
    }
    uint8_t type = data[0];
    size_t declared = data[1];
    const uint8_t *payload = data + 2;
    size_t available = len - 2;

    uint8_t *out = (uint8_t *)malloc(available + 1);
    if (!out) {
        return 0;
    }
    memcpy(out, payload, declared); /* BUG: declared may exceed available -> heap write overflow */
    int r = out[0] ^ type;
    free(out);
    return r;
}
