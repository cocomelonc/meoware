#ifndef MEOWARE_RC6_H
#define MEOWARE_RC6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RC6_KEY_SIZE 16U
#define RC6_BLOCK_SIZE 16U
#define RC6_ROUNDS 20U

/* RC6-32/20/16: 32-bit words, 20 rounds, 16-byte key; little endian. */
void rc6_encrypt_block(uint8_t block[RC6_BLOCK_SIZE], const uint8_t key[RC6_KEY_SIZE]);
void rc6_decrypt_block(uint8_t block[RC6_BLOCK_SIZE], const uint8_t key[RC6_KEY_SIZE]);
bool rc6_cbc_encrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);
bool rc6_cbc_decrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
