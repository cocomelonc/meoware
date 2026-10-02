#ifndef MEOWARE_XTEA_H
#define MEOWARE_XTEA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define XTEA_KEY_SIZE 16U
#define XTEA_BLOCK_SIZE 8U

/* XTEA, 32 cycles (64 half-rounds), explicit big-endian words. */
void xtea_encrypt_block(uint8_t block[XTEA_BLOCK_SIZE], const uint8_t key[XTEA_KEY_SIZE]);
void xtea_decrypt_block(uint8_t block[XTEA_BLOCK_SIZE], const uint8_t key[XTEA_KEY_SIZE]);
/* CBC with PKCS#7 padding. Exact in-place buffers are supported. */
bool xtea_cbc_encrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);
bool xtea_cbc_decrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
