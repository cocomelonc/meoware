#ifndef MEOWARE_SKIPJACK_H
#define MEOWARE_SKIPJACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SKIPJACK_KEY_SIZE 10U
#define SKIPJACK_BLOCK_SIZE 8U
#define SKIPJACK_ROUNDS 32U

/* Standard Skipjack: 80-bit key, 32 rounds, big-endian 16-bit words. */
void skipjack_encrypt_block(uint8_t block[SKIPJACK_BLOCK_SIZE],
                            const uint8_t key[SKIPJACK_KEY_SIZE]);
void skipjack_decrypt_block(uint8_t block[SKIPJACK_BLOCK_SIZE],
                            const uint8_t key[SKIPJACK_KEY_SIZE]);
bool skipjack_cbc_encrypt(const uint8_t key[SKIPJACK_KEY_SIZE],
                          const uint8_t iv[SKIPJACK_BLOCK_SIZE], const uint8_t *input,
                          size_t length, uint8_t *output, size_t capacity, size_t *written);
bool skipjack_cbc_decrypt(const uint8_t key[SKIPJACK_KEY_SIZE],
                          const uint8_t iv[SKIPJACK_BLOCK_SIZE], const uint8_t *input,
                          size_t length, uint8_t *output, size_t capacity, size_t *written);

#endif
