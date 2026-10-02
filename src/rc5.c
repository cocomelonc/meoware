/* author: cocomelonc */
#include "rc5.h"
#include "cbc.h"

/* RC5 key expansion and block transform: https://www.rfc-editor.org/rfc/rfc2040 */
#define RC5_SUBKEYS (2U * (RC5_ROUNDS + 1U))

static uint32_t read_word(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void write_word(uint8_t *bytes, uint32_t word) {
  for (unsigned int i = 0; i < 4; ++i) bytes[i] = (uint8_t)(word >> (8 * i));
}

static uint32_t rotate_left(uint32_t word, uint32_t count) {
  count &= 31;
  return (word << count) | (word >> ((32 - count) & 31));
}

static uint32_t rotate_right(uint32_t word, uint32_t count) {
  count &= 31;
  return (word >> count) | (word << ((32 - count) & 31));
}

static void clear_bytes(void *data, size_t size) {
  volatile uint8_t *cursor = data;
  while (size-- != 0) *cursor++ = 0;
}

static void expand_key(const uint8_t *key, uint32_t subkeys[RC5_SUBKEYS]) {
  uint32_t words[4], left = 0, right = 0;
  unsigned int i = 0, j = 0;
  for (unsigned int n = 0; n < 4; ++n) words[n] = read_word(key + 4 * n);
  subkeys[0] = UINT32_C(0xb7e15163);
  for (unsigned int n = 1; n < RC5_SUBKEYS; ++n) subkeys[n] = subkeys[n - 1] + UINT32_C(0x9e3779b9);
  for (unsigned int n = 0; n < 3 * RC5_SUBKEYS; ++n) {
    left = subkeys[i] = rotate_left(subkeys[i] + left + right, 3);
    right = words[j] = rotate_left(words[j] + left + right, left + right);
    i = (i + 1) % RC5_SUBKEYS;
    j = (j + 1) % 4;
  }
  clear_bytes(words, sizeof(words));
}

static void transform_block(uint8_t *block, const uint8_t *key, bool reverse) {
  uint32_t subkeys[RC5_SUBKEYS];
  uint32_t left = read_word(block), right = read_word(block + 4);
  expand_key(key, subkeys);
  if (reverse) {
    for (unsigned int round = RC5_ROUNDS; round > 0; --round) {
      right = rotate_right(right - subkeys[2 * round + 1], left) ^ left;
      left = rotate_right(left - subkeys[2 * round], right) ^ right;
    }
    right -= subkeys[1];
    left -= subkeys[0];
  } else {
    left += subkeys[0];
    right += subkeys[1];
    for (unsigned int round = 1; round <= RC5_ROUNDS; ++round) {
      left = rotate_left(left ^ right, right) + subkeys[2 * round];
      right = rotate_left(right ^ left, left) + subkeys[2 * round + 1];
    }
  }
  write_word(block, left);
  write_word(block + 4, right);
  clear_bytes(subkeys, sizeof(subkeys));
}

void rc5_encrypt_block(uint8_t block[RC5_BLOCK_SIZE], const uint8_t key[RC5_KEY_SIZE]) {
  transform_block(block, key, false);
}

void rc5_decrypt_block(uint8_t block[RC5_BLOCK_SIZE], const uint8_t key[RC5_KEY_SIZE]) {
  transform_block(block, key, true);
}

bool rc5_cbc_encrypt(const uint8_t key[RC5_KEY_SIZE], const uint8_t iv[RC5_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  return cbc_encrypt(rc5_encrypt_block, RC5_BLOCK_SIZE, key, iv, input, length, output, capacity, written);
}

bool rc5_cbc_decrypt(const uint8_t key[RC5_KEY_SIZE], const uint8_t iv[RC5_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  return cbc_decrypt(rc5_decrypt_block, RC5_BLOCK_SIZE, key, iv, input, length, output, capacity, written);
}
