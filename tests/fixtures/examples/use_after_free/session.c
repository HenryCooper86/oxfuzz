#include "session.h"

#include <stdlib.h>
#include <string.h>

/* Opcodes drive a tiny session state machine:
 *   data[0] == 'O'  -> allocate the session buffer
 *   data[1] == 'C'  -> close (free) the session buffer
 *   data[1] == 'U'  -> use the session buffer
 * Issuing 'U' after the buffer is freed reads dangling memory. */
int run_session(const uint8_t *data, size_t len) {
    if (len < 2 || data[0] != 'O') {
        return 0;
    }
    char *session = (char *)malloc(8);
    if (!session) {
        return 0;
    }
    memcpy(session, "ready\0\0", 8);

    if (data[1] == 'C' || data[1] == 'U') {
        free(session); /* close frees the buffer... */
    }
    if (data[1] == 'U') {
        return session[0]; /* BUG: ...but 'U' still reads it */
    }
    if (data[1] != 'C') {
        free(session);
    }
    return 0;
}
