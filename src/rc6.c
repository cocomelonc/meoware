/* author: cocomelonc */
#include "rc6.h"
#include "cbc.h"

/* RC6 specification: https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf */
#define RC6_SUBKEYS (2U * RC6_ROUNDS + 4U)

static uint32_t read_word(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
         ((uint32_t)bytes[3] << 24);
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

static void expand_key(const uint8_t *key, uint32_t subkeys[RC6_SUBKEYS]) {
  uint32_t words[4], left = 0, right = 0;
  unsigned int i = 0, j = 0;
  for (unsigned int n = 0; n < 4; ++n) words[n] = read_word(key + 4 * n);
  subkeys[0] = UINT32_C(0xb7e15163);
  for (unsigned int n = 1; n < RC6_SUBKEYS; ++n) subkeys[n] = subkeys[n - 1] + UINT32_C(0x9e3779b9);
  for (unsigned int n = 0; n < 3 * RC6_SUBKEYS; ++n) {
    left = subkeys[i] = rotate_left(subkeys[i] + left + right, 3);
    right = words[j] = rotate_left(words[j] + left + right, left + right);
    i = (i + 1) % RC6_SUBKEYS;
    j = (j + 1) % 4;
  }
  clear_bytes(words, sizeof(words));
}

static void transform_block(uint8_t *block, const uint8_t *key, bool reverse) {
  uint32_t subkeys[RC6_SUBKEYS];
  uint32_t a = read_word(block), b = read_word(block + 4);
  uint32_t c = read_word(block + 8), d = read_word(block + 12);
  expand_key(key, subkeys);
  if (reverse) {
    c -= subkeys[2 * RC6_ROUNDS + 3];
    a -= subkeys[2 * RC6_ROUNDS + 2];
    for (unsigned int round = RC6_ROUNDS; round > 0; --round) {
      uint32_t saved = d;
      d = c;
      c = b;
      b = a;
      a = saved;
      uint32_t u = rotate_left(d * (2 * d + 1), 5);
      uint32_t t = rotate_left(b * (2 * b + 1), 5);
      c = rotate_right(c - subkeys[2 * round + 1], t) ^ u;
      a = rotate_right(a - subkeys[2 * round], u) ^ t;
    }
    d -= subkeys[1];
    b -= subkeys[0];
  } else {
    b += subkeys[0];
    d += subkeys[1];
    for (unsigned int round = 1; round <= RC6_ROUNDS; ++round) {
      uint32_t t = rotate_left(b * (2 * b + 1), 5);
      uint32_t u = rotate_left(d * (2 * d + 1), 5);
      a = rotate_left(a ^ t, u) + subkeys[2 * round];
      c = rotate_left(c ^ u, t) + subkeys[2 * round + 1];
      uint32_t saved = a;
      a = b;
      b = c;
      c = d;
      d = saved;
    }
    a += subkeys[2 * RC6_ROUNDS + 2];
    c += subkeys[2 * RC6_ROUNDS + 3];
  }
  write_word(block, a);
  write_word(block + 4, b);
  write_word(block + 8, c);
  write_word(block + 12, d);
  clear_bytes(subkeys, sizeof(subkeys));
}

void rc6_encrypt_block(uint8_t block[RC6_BLOCK_SIZE], const uint8_t key[RC6_KEY_SIZE]) {
  transform_block(block, key, false);
}

void rc6_decrypt_block(uint8_t block[RC6_BLOCK_SIZE], const uint8_t key[RC6_KEY_SIZE]) {
  transform_block(block, key, true);
}

bool rc6_cbc_encrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE],
                     const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                     size_t *written) {
  return cbc_encrypt(rc6_encrypt_block, RC6_BLOCK_SIZE, key, iv, input, length, output, capacity,
                     written);
}

bool rc6_cbc_decrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE],
                     const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                     size_t *written) {
  return cbc_decrypt(rc6_decrypt_block, RC6_BLOCK_SIZE, key, iv, input, length, output, capacity,
                     written);
}
