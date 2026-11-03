/* Public entry points: message header validation and the record loop. */
#include <string.h>

#include "tlv_internal.h"

static const uint8_t TLV_MAGIC[3] = {'T', 'L', 'V'};

int tlv_decode(const uint8_t *data, size_t len, tlv_message *msg) {
    tlv_cursor cur;
    const uint8_t *magic = NULL;
    int rc;

    if (msg == NULL || (data == NULL && len != 0)) {
        return TLV_ERR_ARGUMENT;
    }
    memset(msg, 0, sizeof(*msg));
    tlv_cursor_init(&cur, data, len);

    if ((rc = tlv_read_bytes(&cur, sizeof(TLV_MAGIC), &magic)) != TLV_OK) {
        return rc;
    }
    if (memcmp(magic, TLV_MAGIC, sizeof(TLV_MAGIC)) != 0) {
        return TLV_ERR_MAGIC;
    }
    if ((rc = tlv_read_u8(&cur, &msg->version)) != TLV_OK) {
        return rc;
    }
    if (msg->version != TLV_VERSION) {
        return TLV_ERR_VERSION;
    }

    while (tlv_cursor_remaining(&cur) > 0) {
        if (msg->count == TLV_MAX_RECORDS) {
            rc = TLV_ERR_TOO_MANY;
            break;
        }
        tlv_record rec;
        memset(&rec, 0, sizeof(rec));
        rc = tlv_record_decode(&cur, &rec);
        if (rc != TLV_OK) {
            break;
        }
        msg->records[msg->count] = rec;
        msg->count += 1;
    }

    if (rc != TLV_OK) {
        tlv_message_free(msg);
        return rc;
    }
    return TLV_OK;
}

void tlv_message_free(tlv_message *msg) {
    if (msg == NULL) {
        return;
    }
    for (size_t i = 0; i < msg->count; i++) {
        tlv_record_release(&msg->records[i]);
    }
    msg->count = 0;
}
