#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct decoder { unsigned state; };
static struct decoder *decoder_create(unsigned mode) {
    struct decoder *result = malloc(sizeof(*result));
    if (result) result->state = mode;
    return result;
}
static int decoder_feed(struct decoder *decoder, const uint8_t *data, size_t size) {
    if (!decoder || !data) return -1;
    unsigned value = decoder->state;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == 0xff) value ^= 0x55;
        else if (data[i] < 16) value += data[i];
        else value = (value * 33 + data[i]) & 0xffff;
    }
    decoder->state = value;
    return (int)value;
}
static void decoder_release(struct decoder *decoder) { free(decoder); }
int decode_message(const uint8_t *data, size_t size) {
    if (!data || size < 2) return -1;
    struct decoder *decoder = decoder_create(data[0] & 3);
    if (!decoder) return -2;
    int result = decoder_feed(decoder, data + 1, size - 1);
    decoder_release(decoder);
    return result;
}
