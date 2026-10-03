#ifndef MEOWARE_A51_H
#define MEOWARE_A51_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define A51_KEY_SIZE 8U
#define A51_IV_SIZE 3U
#define A51_FRAME_MASK UINT32_C(0x3fffff)

/* A5/1 initialization: key byte 0 first, bits LSB first; raw 22-bit COUNT.
 * File adaptation: continuous MSB-first keystream after initialization, no
 * GSM burst framing or padding. The same operation encrypts and decrypts.
 * Supports exact in-place operation, not partially overlapping buffers. */
bool a51_crypt(const uint8_t key[A51_KEY_SIZE], uint32_t frame,
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
