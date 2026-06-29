#include "optional.h"

#include <stdlib.h>
#include <string.h>

/* Returns a freshly allocated record for a known tag, or NULL when the tag is
 * the "missing" marker '?'. The caller below forgets to handle NULL. */
static char *lookup_record(uint8_t tag) {
    if (tag == '?') {
        return NULL; /* missing record */
    }
    char *rec = (char *)malloc(4);
    if (rec) {
        memset(rec, tag, 4);
    }
    return rec;
}

int parse_optional(const uint8_t *data, size_t len) {
    if (len < 1) {
        return 0;
    }
    char *rec = lookup_record(data[0]);
    int first = rec[0]; /* BUG: rec is NULL when data[0] == '?' */
    free(rec);
    return first;
}
