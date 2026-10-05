/* author: cocomelonc */
#include "speck.h"
#include "cbc.h"

/* https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf */
static uint64_t read_word(const uint8_t *bytes) {
  uint64_t word = 0;
  for (unsigned int i = 0; i < 8; ++i) word |= (uint64_t)bytes[i] << (8 * i);
  return word;
}

static void write_word(uint8_t *bytes, uint64_t word) {
  for (unsigned int i = 0; i < 8; ++i) bytes[i] = (uint8_t)(word >> (8 * i));
}

/* Counts are fixed at 3 or 8 by the cipher. */
static uint64_t rotate_left(uint64_t word, unsigned int count) {
  return (word << count) | (word >> (64 - count));
}

static uint64_t rotate_right(uint64_t word, unsigned int count) {
  return (word >> count) | (word << (64 - count));
}

static void expand_key(const uint8_t *key, uint64_t subkeys[SPECK_ROUNDS]) {
  uint64_t next = read_word(key + 8);
  subkeys[0] = read_word(key);
  for (unsigned int i = 0; i + 1 < SPECK_ROUNDS; ++i) {
    next = (rotate_right(next, 8) + subkeys[i]) ^ i;
    subkeys[i + 1] = rotate_left(subkeys[i], 3) ^ next;
  }
}

static void transform_block(uint8_t *block, const uint8_t *key, bool reverse) {
  uint64_t subkeys[SPECK_ROUNDS];
  /* The reference serializes (y, x), each as a little-endian 64-bit word. */
  uint64_t x = read_word(block + 8), y = read_word(block);
  expand_key(key, subkeys);
  for (unsigned int i = 0; i < SPECK_ROUNDS; ++i) {
    if (reverse) {
      y = rotate_right(y ^ x, 3);
      x = rotate_left((x ^ subkeys[SPECK_ROUNDS - 1 - i]) - y, 8);
    } else {
      x = (rotate_right(x, 8) + y) ^ subkeys[i];
      y = rotate_left(y, 3) ^ x;
    }
  }
  write_word(block, y);
  write_word(block + 8, x);
  volatile uint64_t *cursor = subkeys;
  for (unsigned int i = 0; i < SPECK_ROUNDS; ++i) cursor[i] = 0;
}

void speck_encrypt_block(uint8_t block[SPECK_BLOCK_SIZE], const uint8_t key[SPECK_KEY_SIZE]) {
  transform_block(block, key, false);
}

void speck_decrypt_block(uint8_t block[SPECK_BLOCK_SIZE], const uint8_t key[SPECK_KEY_SIZE]) {
  transform_block(block, key, true);
}

bool speck_cbc_encrypt(const uint8_t key[SPECK_KEY_SIZE], const uint8_t iv[SPECK_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  return cbc_encrypt(speck_encrypt_block, SPECK_BLOCK_SIZE, key, iv, input, length, output,
                     capacity, written);
}

bool speck_cbc_decrypt(const uint8_t key[SPECK_KEY_SIZE], const uint8_t iv[SPECK_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  return cbc_decrypt(speck_decrypt_block, SPECK_BLOCK_SIZE, key, iv, input, length, output,
                     capacity, written);
}
