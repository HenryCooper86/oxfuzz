#include "fuzz_me.h"

/* The canonical libFuzzer example, verbatim in spirit.
 *
 * The `&&` short-circuits left-to-right: by the time `data[3]` is evaluated,
 * the first three bytes are already known to be 'F','U','Z'. If the heap
 * allocation backing `data` is only 3 bytes long, reading `data[3]` is a
 * one-byte heap-buffer-overflow that ASan flags within milliseconds.
 */
int FuzzMe(const uint8_t *data, size_t size) {
    return size >= 3 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' &&
           data[3] == 'Z'; /* BUG: reads data[3] when size == 3 */
}
