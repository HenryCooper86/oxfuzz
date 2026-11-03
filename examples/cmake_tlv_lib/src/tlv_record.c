/* Per-record decoding: reads one type/length/value triple and converts the
 * value according to its type. */
#include <stdlib.h>
#include <string.h>

#include "tlv_internal.h"

static int decode_u32(const uint8_t *value, uint16_t length, tlv_record *rec) {
    if (length != 4) {
        return TLV_ERR_LENGTH;
    }
    rec->value.u32 = ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
                     ((uint32_t)value[2] << 8) | (uint32_t)value[3];
    return TLV_OK;
}

/* Makes an owned, NUL-terminated copy of a STRING value. The allocation is
 * sized for the payload only; the terminator is then written one byte past
 * the end of the block. */
static int decode_string(const uint8_t *value, uint16_t length, tlv_record *rec) {
    char *copy = malloc(length); /* BUG: needs length + 1 for the NUL terminator */
    if (copy == NULL) {
        return TLV_ERR_NOMEM;
    }
    memcpy(copy, value, length);
    copy[length] = '\0'; /* BUG: one-byte heap-buffer-overflow write */
    rec->value.str = copy;
    return TLV_OK;
}

int tlv_record_decode(tlv_cursor *cur, tlv_record *rec) {
    uint8_t type = 0;
    uint16_t length = 0;
    const uint8_t *value = NULL;
    int rc;

    if ((rc = tlv_read_u8(cur, &type)) != TLV_OK) {
        return rc;
    }
    if ((rc = tlv_read_u16be(cur, &length)) != TLV_OK) {
        return rc;
    }
    if ((rc = tlv_read_bytes(cur, length, &value)) != TLV_OK) {
        return rc;
    }

    rec->type = type;
    rec->length = length;
    switch (type) {
    case TLV_TYPE_U32:
        return decode_u32(value, length, rec);
    case TLV_TYPE_STRING:
        return decode_string(value, length, rec);
    case TLV_TYPE_BLOB:
        rec->value.blob = value;
        return TLV_OK;
    default:
        return TLV_ERR_TYPE;
    }
}

void tlv_record_release(tlv_record *rec) {
    if (rec->type == TLV_TYPE_STRING) {
        free(rec->value.str);
        rec->value.str = NULL;
    }
}
