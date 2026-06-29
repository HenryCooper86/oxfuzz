#include "token.h"

#include <stdlib.h>
#include <string.h>

/* Allocates a copy of the token first, then validates its length. On the error
 * path the function returns without freeing -- a textbook leak. */
int parse_token(const uint8_t *data, size_t len) {
    if (len < 1) {
        return 0;
    }
    size_t tok_len = data[0];
    char *tok = (char *)malloc(tok_len + 1);
    if (!tok) {
        return 0;
    }
    size_t available = len - 1;
    size_t n = tok_len < available ? tok_len : available;
    memcpy(tok, data + 1, n);
    tok[n] = '\0';

    if (tok_len > 4) {
        return -1; /* BUG: early return leaks `tok` */
    }

    int r = tok[0];
    free(tok);
    return r;
}
