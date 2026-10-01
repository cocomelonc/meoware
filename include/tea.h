#ifndef MEOWARE_TEA_H
#define MEOWARE_TEA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEA_KEY_SIZE 16U
#define TEA_BLOCK_SIZE 8U

/* Classic TEA, 32 cycles, with explicit big-endian word serialization. */
void tea_encrypt_block(uint8_t block[TEA_BLOCK_SIZE], const uint8_t key[TEA_KEY_SIZE]);
void tea_decrypt_block(uint8_t block[TEA_BLOCK_SIZE], const uint8_t key[TEA_KEY_SIZE]);
/* CBC with PKCS#7 padding. Exact in-place buffers are supported. */
bool tea_cbc_encrypt(const uint8_t key[TEA_KEY_SIZE], const uint8_t iv[TEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);
bool tea_cbc_decrypt(const uint8_t key[TEA_KEY_SIZE], const uint8_t iv[TEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
