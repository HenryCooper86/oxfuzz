/* Native libFuzzer example: deterministic in-place bit mutation. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                              size_t max_size, unsigned int seed) {
    if (size == 0) {
        if (max_size == 0) return 0;
        data[0] = (uint8_t)seed;
        return 1;
    }
    size_t length = size < max_size ? size : max_size;
    if (length) data[seed % length] ^= (uint8_t)(1U << (seed % 8));
    return length;
}
#ifdef __cplusplus
}
#endif
