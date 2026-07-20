#include "number.h"

#include <string.h>

/* True for the bytes that may appear inside a JSON number token. */
static int is_number_byte(uint8_t c) {
    return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
           c == 'e' || c == 'E';
}

/* Length of the leading run of number bytes in `data`. */
static size_t number_span(const uint8_t *data, size_t len) {
    size_t n = 0;
    while (n < len && is_number_byte(data[n])) {
        n++;
    }
    return n;
}

/* Copies the leading numeric literal into a fixed 32-byte stack buffer and
 * folds its digits into an integer value. */
int parse_number(const uint8_t *data, size_t len) {
    char token[32];
    size_t span = number_span(data, len);

    memcpy(token, data, span); /* BUG: span may exceed sizeof(token) -> stack overflow */

    int value = 0;
    for (size_t i = 0; i < span; i++) {
        if (token[i] >= '0' && token[i] <= '9') {
            value = value * 10 + (token[i] - '0');
        }
    }
    return value;
}
