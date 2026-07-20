/* AFL++ persistent-mode "packet parser" example.
 *
 * Provenance: modeled on the AFLplusplus persistent-mode harness style, whose
 *   `LLVMFuzzerTestOneInput`-compatible entry point is driven in a tight
 *   __AFL_LOOP (Apache-2.0). AFL++ calls the exact same libFuzzer-compatible
 *   (data, len) entry point that libFuzzer and honggfuzz do; persistent mode
 *   just re-invokes it many times per process for speed. Written from scratch.
 *
 * Bug class: heap-buffer-overflow (WRITE).
 * Expected finding: ASan reports a heap write past the end of the output buffer
 *   whenever the declared length field (data[1]) exceeds the number of payload
 *   bytes actually present (len - 2).
 */
#ifndef OXFUZZ_EXAMPLE_PACKET_H
#define OXFUZZ_EXAMPLE_PACKET_H

#include <stddef.h>
#include <stdint.h>

/* Parses [type:1][declared_len:1][payload...] and copies the payload out. */
int parse_packet(const uint8_t *data, size_t len);

#endif /* OXFUZZ_EXAMPLE_PACKET_H */
