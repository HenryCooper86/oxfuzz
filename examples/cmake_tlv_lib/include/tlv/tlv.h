/* tlvlib: a tiny type-length-value message decoder.
 *
 * Wire format (all multi-byte integers are big-endian):
 *
 *   magic   3 bytes  "TLV"
 *   version 1 byte   must be TLV_VERSION
 *   records repeated until the end of the input:
 *     type    1 byte   one of the TLV_TYPE_* values
 *     length  2 bytes  number of value bytes that follow
 *     value   `length` bytes
 *
 * The public API is the pair tlv_decode() / tlv_message_free(). Everything
 * else in src/ is internal and declared in src/tlv_internal.h.
 *
 * This is an oxfuzz example target with one deliberately planted bug; see
 * README.md in this directory.
 */
#ifndef TLVLIB_TLV_H
#define TLVLIB_TLV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLV_VERSION 1u
#define TLV_MAX_RECORDS 16u

enum tlv_status {
    TLV_OK = 0,
    TLV_ERR_ARGUMENT = -1,
    TLV_ERR_TRUNCATED = -2,
    TLV_ERR_MAGIC = -3,
    TLV_ERR_VERSION = -4,
    TLV_ERR_TOO_MANY = -5,
    TLV_ERR_TYPE = -6,
    TLV_ERR_LENGTH = -7,
    TLV_ERR_NOMEM = -8
};

enum tlv_type {
    TLV_TYPE_U32 = 0x01,    /* value is a 4-byte big-endian integer */
    TLV_TYPE_STRING = 0x02, /* value is text, decoded to a NUL-terminated copy */
    TLV_TYPE_BLOB = 0x03    /* value is opaque bytes, referenced in place */
};

typedef struct tlv_record {
    uint8_t type;
    uint16_t length;
    union {
        uint32_t u32;
        char *str;            /* owned; released by tlv_message_free() */
        const uint8_t *blob;  /* borrowed; points into the caller's input */
    } value;
} tlv_record;

typedef struct tlv_message {
    uint8_t version;
    size_t count;
    tlv_record records[TLV_MAX_RECORDS];
} tlv_message;

/* Decodes `len` bytes at `data` into `msg`. Returns TLV_OK or a negative
 * tlv_status. On success the caller must release `msg` with
 * tlv_message_free(); on failure `msg` holds no owned memory. */
int tlv_decode(const uint8_t *data, size_t len, tlv_message *msg);

/* Releases memory owned by a message filled in by tlv_decode(). */
void tlv_message_free(tlv_message *msg);

#ifdef __cplusplus
}
#endif

#endif /* TLVLIB_TLV_H */
