#include <stddef.h>
#include <stdint.h>

unsigned qualification_parse(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    if (data[0] != 'O' || data[1] != 'X') return 1;
    if (data[2] == 0 && data[3] == 255) return 2;
    return 3;
}
