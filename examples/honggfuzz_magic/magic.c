#include "magic.h"

#include <stdlib.h>

/* The honggfuzz introductory target: a staged magic-byte comparison ending in
 * abort(). Each additional matched byte is a fresh branch, so a coverage-guided
 * fuzzer walks the comparison open one byte at a time rather than having to
 * guess all four at once. */
int match_magic(const uint8_t *data, size_t len) {
    if (len >= 4 && data[0] == 'A' && data[1] == 'B' && data[2] == 'C' &&
        data[3] == 'D') {
        abort(); /* BUG: reachable crash on input "ABCD..." */
    }
    return 0;
}
