#ifndef MEOWARE_SPECK_H
#define MEOWARE_SPECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SPECK_KEY_SIZE 16U
#define SPECK_BLOCK_SIZE 16U
#define SPECK_ROUNDS 32U

/* Speck128/128: 32 rounds; reference-guide little-endian byte/word order. */
void speck_encrypt_block(uint8_t block[SPECK_BLOCK_SIZE], const uint8_t key[SPECK_KEY_SIZE]);
void speck_decrypt_block(uint8_t block[SPECK_BLOCK_SIZE], const uint8_t key[SPECK_KEY_SIZE]);
bool speck_cbc_encrypt(const uint8_t key[SPECK_KEY_SIZE], const uint8_t iv[SPECK_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);
bool speck_cbc_decrypt(const uint8_t key[SPECK_KEY_SIZE], const uint8_t iv[SPECK_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
