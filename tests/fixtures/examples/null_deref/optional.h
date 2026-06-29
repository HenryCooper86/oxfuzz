/* NULL-pointer-dereference example.
 *
 * Provenance: the "lookup may fail but the caller forgot to check" bug -- a
 * helper returns NULL on a missing/odd field and the caller dereferences it
 * unconditionally. ASan/UBSan report it as a SEGV / null deref.
 *
 * Bug class: NULL pointer dereference (SIGSEGV).
 * Expected finding: a crash when the input selects the failing lookup branch
 *   (first byte '?'), causing a dereference of the NULL return value.
 */
#ifndef HF_EXAMPLE_OPTIONAL_H
#define HF_EXAMPLE_OPTIONAL_H

#include <stddef.h>
#include <stdint.h>

/* Looks up a record by tag and reads its first field. */
int parse_optional(const uint8_t *data, size_t len);

#endif /* HF_EXAMPLE_OPTIONAL_H */
