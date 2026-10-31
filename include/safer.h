#ifndef MEOWARE_SAFER_H
#define MEOWARE_SAFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SAFER_KEY_SIZE 8U
#define SAFER_BLOCK_SIZE 8U
#define SAFER_ROUNDS 6U
#define SAFER_SCHEDULE_SIZE ((2U * SAFER_ROUNDS + 1U) * SAFER_BLOCK_SIZE)

/* Original SAFER K-64, six rounds, unstrengthened key schedule.
 * Byte-oriented serialization; valid arrays are required by the block API. */
void safer_expand_key(const uint8_t key[SAFER_KEY_SIZE], uint8_t schedule[SAFER_SCHEDULE_SIZE]);
void safer_encrypt_prepared(uint8_t block[SAFER_BLOCK_SIZE], const uint8_t schedule[SAFER_SCHEDULE_SIZE]);
void safer_decrypt_prepared(uint8_t block[SAFER_BLOCK_SIZE], const uint8_t schedule[SAFER_SCHEDULE_SIZE]);
void safer_encrypt_block(uint8_t block[SAFER_BLOCK_SIZE], const uint8_t key[SAFER_KEY_SIZE]);
void safer_decrypt_block(uint8_t block[SAFER_BLOCK_SIZE], const uint8_t key[SAFER_KEY_SIZE]);
bool safer_cbc_encrypt(const uint8_t key[SAFER_KEY_SIZE], const uint8_t iv[SAFER_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written);
bool safer_cbc_decrypt(const uint8_t key[SAFER_KEY_SIZE], const uint8_t iv[SAFER_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written);

#endif
