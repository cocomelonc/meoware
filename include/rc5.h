#ifndef MEOWARE_RC5_H
#define MEOWARE_RC5_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RC5_KEY_SIZE 16U
#define RC5_BLOCK_SIZE 8U
#define RC5_ROUNDS 12U

/* RC5-32/12/16: 32-bit words, 12 rounds, 16-byte key; little endian. */
void rc5_encrypt_block(uint8_t block[RC5_BLOCK_SIZE], const uint8_t key[RC5_KEY_SIZE]);
void rc5_decrypt_block(uint8_t block[RC5_BLOCK_SIZE], const uint8_t key[RC5_KEY_SIZE]);
bool rc5_cbc_encrypt(const uint8_t key[RC5_KEY_SIZE], const uint8_t iv[RC5_BLOCK_SIZE],
                     const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                     size_t *written);
bool rc5_cbc_decrypt(const uint8_t key[RC5_KEY_SIZE], const uint8_t iv[RC5_BLOCK_SIZE],
                     const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                     size_t *written);

#endif
