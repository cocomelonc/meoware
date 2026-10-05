/* author: cocomelonc */
#include "tea.h"
#include "cbc.h"

/* Wheeler and Needham, TEA (1994):
 * https://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html */
static uint32_t read_word(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
         bytes[3];
}

static void write_word(uint8_t *bytes, uint32_t word) {
  bytes[0] = (uint8_t)(word >> 24);
  bytes[1] = (uint8_t)(word >> 16);
  bytes[2] = (uint8_t)(word >> 8);
  bytes[3] = (uint8_t)word;
}

static void clear_bytes(void *data, size_t length) {
  volatile uint8_t *cursor = data;
  while (length-- != 0) *cursor++ = 0;
}

static void transform_block(uint8_t *block, const uint8_t *key, bool reverse) {
  uint32_t halves[2] = {read_word(block), read_word(block + 4)};
  uint32_t words[4];
  const uint32_t delta = UINT32_C(0x9e3779b9);
  uint32_t schedule = reverse ? UINT32_C(0xc6ef3720) : 0;
  unsigned int cycle;
  for (cycle = 0; cycle < 4; ++cycle) words[cycle] = read_word(key + cycle * 4);
  for (cycle = 0; cycle < 32; ++cycle) {
    if (reverse) {
      halves[1] -=
          ((halves[0] << 4) + words[2]) ^ (halves[0] + schedule) ^ ((halves[0] >> 5) + words[3]);
      halves[0] -=
          ((halves[1] << 4) + words[0]) ^ (halves[1] + schedule) ^ ((halves[1] >> 5) + words[1]);
      schedule -= delta;
    } else {
      schedule += delta;
      halves[0] +=
          ((halves[1] << 4) + words[0]) ^ (halves[1] + schedule) ^ ((halves[1] >> 5) + words[1]);
      halves[1] +=
          ((halves[0] << 4) + words[2]) ^ (halves[0] + schedule) ^ ((halves[0] >> 5) + words[3]);
    }
  }
  write_word(block, halves[0]);
  write_word(block + 4, halves[1]);
  clear_bytes(words, sizeof(words));
  clear_bytes(halves, sizeof(halves));
}

void tea_encrypt_block(uint8_t block[TEA_BLOCK_SIZE], const uint8_t key[TEA_KEY_SIZE]) {
  transform_block(block, key, false);
}

void tea_decrypt_block(uint8_t block[TEA_BLOCK_SIZE], const uint8_t key[TEA_KEY_SIZE]) {
  transform_block(block, key, true);
}

bool tea_cbc_encrypt(const uint8_t key[TEA_KEY_SIZE], const uint8_t iv[TEA_BLOCK_SIZE],
                     const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                     size_t *written) {
  return cbc_encrypt(tea_encrypt_block, TEA_BLOCK_SIZE, key, iv, input, length, output, capacity,
                     written);
}

bool tea_cbc_decrypt(const uint8_t key[TEA_KEY_SIZE], const uint8_t iv[TEA_BLOCK_SIZE],
                     const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                     size_t *written) {
  return cbc_decrypt(tea_decrypt_block, TEA_BLOCK_SIZE, key, iv, input, length, output, capacity,
                     written);
}
