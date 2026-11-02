#ifndef MEOWARE_FEAL8_H
#define MEOWARE_FEAL8_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FEAL8_KEY_SIZE 8U
#define FEAL8_BLOCK_SIZE 8U
#define FEAL8_ROUNDS 8U
#define FEAL8_SCHEDULE_SIZE 32U

/* Standard FEAL-8: 64-bit key/block, eight rounds, no key parity processing.
 * All byte strings, including the sixteen 16-bit subkeys, are big-endian.
 * Block functions require valid arrays and support unaligned buffers. */
void feal8_expand_key(const uint8_t key[FEAL8_KEY_SIZE], uint8_t schedule[FEAL8_SCHEDULE_SIZE]);
void feal8_encrypt_prepared(uint8_t block[FEAL8_BLOCK_SIZE],
                            const uint8_t schedule[FEAL8_SCHEDULE_SIZE]);
void feal8_decrypt_prepared(uint8_t block[FEAL8_BLOCK_SIZE],
                            const uint8_t schedule[FEAL8_SCHEDULE_SIZE]);
void feal8_encrypt_block(uint8_t block[FEAL8_BLOCK_SIZE], const uint8_t key[FEAL8_KEY_SIZE]);
void feal8_decrypt_block(uint8_t block[FEAL8_BLOCK_SIZE], const uint8_t key[FEAL8_KEY_SIZE]);
bool feal8_cbc_encrypt(const uint8_t key[FEAL8_KEY_SIZE], const uint8_t iv[FEAL8_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written);
bool feal8_cbc_decrypt(const uint8_t key[FEAL8_KEY_SIZE], const uint8_t iv[FEAL8_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written);

#endif
