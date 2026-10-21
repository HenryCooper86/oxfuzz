#include <stddef.h>
#include <stdint.h>

static int parse_payload(const uint8_t *data, size_t size) {
    unsigned sum = 0;
    for (size_t i = 0; i < size; ++i) sum += data[i];
    if (size > 2 && data[0] == 0x41 && data[1] == 0x42) return (int)(sum ^ 0x1234);
    if (size > 4 && data[2] == 0xff) return (int)(sum | 0x100);
    return (int)sum;
}

int parse_record(const uint8_t *data, size_t size) {
    if (!data || size < 4) return -1;
    if (data[0] != 0xa5) return -2;
    size_t length = (size_t)data[1] | ((size_t)data[2] << 8);
    if (length > size - 4) return -3;
    if (data[3] == 1) return parse_payload(data + 4, length);
    if (data[3] == 2 && length >= 2) return parse_payload(data + 4, length - 1);
    return 0;
}
