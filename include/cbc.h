#ifndef MEOWARE_CBC_H
#define MEOWARE_CBC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CBC_MAX_BLOCK_SIZE 16U

typedef void (*CbcBlockTransform)(uint8_t *block, const uint8_t *key);

/* Shared CBC/PKCS#7 framing for 8- or 16-byte blocks. Exact in-place
 * operation is supported; other overlapping buffers are not supported.
 * Decryption requires capacity >= ciphertext length and clears output on
 * invalid padding. The caller's IV is never modified. */
bool cbc_encrypt(CbcBlockTransform transform, size_t block_size, const uint8_t *key,
                 const uint8_t *iv, const uint8_t *input, size_t length, uint8_t *output,
                 size_t capacity, size_t *written);
bool cbc_decrypt(CbcBlockTransform transform, size_t block_size, const uint8_t *key,
                 const uint8_t *iv, const uint8_t *input, size_t length, uint8_t *output,
                 size_t capacity, size_t *written);

#endif
