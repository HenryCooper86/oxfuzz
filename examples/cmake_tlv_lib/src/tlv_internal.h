/* Internal helpers shared by the tlvlib translation units. Not installed and
 * not part of the public API. */
#ifndef TLVLIB_TLV_INTERNAL_H
#define TLVLIB_TLV_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "tlv/tlv.h"

/* A bounds-checked read position over the caller's input buffer. */
typedef struct tlv_cursor {
    const uint8_t *data;
    size_t len;
    size_t pos;
} tlv_cursor;

/* tlv_reader.c */
void tlv_cursor_init(tlv_cursor *cur, const uint8_t *data, size_t len);
size_t tlv_cursor_remaining(const tlv_cursor *cur);
int tlv_read_u8(tlv_cursor *cur, uint8_t *out);
int tlv_read_u16be(tlv_cursor *cur, uint16_t *out);
int tlv_read_bytes(tlv_cursor *cur, size_t n, const uint8_t **out);

/* tlv_record.c */
int tlv_record_decode(tlv_cursor *cur, tlv_record *rec);
void tlv_record_release(tlv_record *rec);

#endif /* TLVLIB_TLV_INTERNAL_H */
