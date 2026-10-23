/* Native AFL++ example: mutate within the engine-owned input buffer. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif
void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    uint32_t *state = (uint32_t *)malloc(sizeof(*state));
    if (!state) abort();
    *state = seed ? seed : 1;
    return state;
}

size_t afl_custom_fuzz(void *opaque, unsigned char *buf, size_t size,
                       unsigned char **out_buf, unsigned char *add_buf,
                       size_t add_size, size_t max_size) {
    (void)add_buf;
    (void)add_size;
    uint32_t *state = (uint32_t *)opaque;
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    size_t length = size < max_size ? size : max_size;
    if (length) buf[*state % length] ^= (unsigned char)(1U << (*state % 8));
    *out_buf = buf;
    return length;
}

void afl_custom_deinit(void *opaque) {
    free(opaque);
}
#ifdef __cplusplus
}
#endif
