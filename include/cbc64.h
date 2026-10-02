#ifndef MEOWARE_CBC64_H
#define MEOWARE_CBC64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CBC64_BLOCK_SIZE 8U

typedef void (*Cbc64BlockTransform)(uint8_t *block, const uint8_t *key);

/* Shared CBC/PKCS#7 framing for 64-bit block ciphers. Exact in-place
 * operation is supported; other overlapping buffers are not supported.
 * Decryption requires capacity >= ciphertext length and clears output on
 * invalid padding. The caller's IV is never modified. */
bool cbc64_encrypt(Cbc64BlockTransform transform, const uint8_t *key, const uint8_t iv[8],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);
bool cbc64_decrypt(Cbc64BlockTransform transform, const uint8_t *key, const uint8_t iv[8],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
