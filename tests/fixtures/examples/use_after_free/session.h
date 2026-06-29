/* Use-after-free example.
 *
 * Provenance: the classic state-machine UAF -- an object is freed on one
 * branch but a later branch still reads through the dangling pointer. Mirrors
 * many protocol/parser CVEs.
 *
 * Bug class: heap-use-after-free (READ).
 * Expected finding: ASan reports a read of freed memory when the input opens a
 *   session (first byte 'O') and then issues a use command (second byte 'U').
 */
#ifndef HF_EXAMPLE_SESSION_H
#define HF_EXAMPLE_SESSION_H

#include <stddef.h>
#include <stdint.h>

/* Drives a tiny open/close/use state machine over the input bytes. */
int run_session(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_SESSION_H */
