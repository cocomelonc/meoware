#ifndef MEOWARE_CAMELLIA_H
#define MEOWARE_CAMELLIA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CAMELLIA_KEY_SIZE 16U
#define CAMELLIA_BLOCK_SIZE 16U
#define CAMELLIA_ROUNDS 18U

/* Camellia-128, RFC 3713; big-endian words. */
void camellia_encrypt_block(uint8_t block[CAMELLIA_BLOCK_SIZE], const uint8_t key[CAMELLIA_KEY_SIZE]);
void camellia_decrypt_block(uint8_t block[CAMELLIA_BLOCK_SIZE], const uint8_t key[CAMELLIA_KEY_SIZE]);
bool camellia_cbc_encrypt(const uint8_t key[CAMELLIA_KEY_SIZE], const uint8_t iv[CAMELLIA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);
bool camellia_cbc_decrypt(const uint8_t key[CAMELLIA_KEY_SIZE], const uint8_t iv[CAMELLIA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
