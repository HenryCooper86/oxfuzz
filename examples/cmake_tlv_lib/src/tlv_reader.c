/* Bounds-checked cursor primitives. Every read verifies the requested byte
 * count against what remains in the input before touching it. */
#include "tlv_internal.h"

void tlv_cursor_init(tlv_cursor *cur, const uint8_t *data, size_t len) {
    cur->data = data;
    cur->len = len;
    cur->pos = 0;
}

size_t tlv_cursor_remaining(const tlv_cursor *cur) {
    return cur->len - cur->pos;
}

int tlv_read_u8(tlv_cursor *cur, uint8_t *out) {
    if (tlv_cursor_remaining(cur) < 1) {
        return TLV_ERR_TRUNCATED;
    }
    *out = cur->data[cur->pos];
    cur->pos += 1;
    return TLV_OK;
}

int tlv_read_u16be(tlv_cursor *cur, uint16_t *out) {
    if (tlv_cursor_remaining(cur) < 2) {
        return TLV_ERR_TRUNCATED;
    }
    *out = (uint16_t)((cur->data[cur->pos] << 8) | cur->data[cur->pos + 1]);
    cur->pos += 2;
    return TLV_OK;
}

int tlv_read_bytes(tlv_cursor *cur, size_t n, const uint8_t **out) {
    if (tlv_cursor_remaining(cur) < n) {
        return TLV_ERR_TRUNCATED;
    }
    *out = cur->data + cur->pos;
    cur->pos += n;
    return TLV_OK;
}
