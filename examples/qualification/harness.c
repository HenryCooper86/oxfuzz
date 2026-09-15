#include <stddef.h>
#include <stdint.h>

unsigned qualification_parse(const uint8_t *data, size_t size);
static volatile unsigned observed;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    observed = qualification_parse(data, size);
    return 0;
}
