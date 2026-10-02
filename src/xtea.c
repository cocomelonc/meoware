/* author: cocomelonc */
#include "xtea.h"
#include "cbc.h"

/* Needham and Wheeler, Tea extensions (1997):
 * https://www.cix.co.uk/~klockstone/xtea.pdf */
static uint32_t read_word(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | bytes[3];
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
  uint32_t halves[2] = { read_word(block), read_word(block + 4) };
  uint32_t words[4];
  const uint32_t delta = UINT32_C(0x9e3779b9);
  uint32_t schedule = reverse ? UINT32_C(0xc6ef3720) : 0;
  unsigned int cycle;
  for (cycle = 0; cycle < 4; ++cycle) words[cycle] = read_word(key + cycle * 4);
  for (cycle = 0; cycle < 32; ++cycle) {
    if (reverse) {
      halves[1] -= (((halves[0] << 4) ^ (halves[0] >> 5)) + halves[0]) ^ (schedule + words[(schedule >> 11) & 3]);
      schedule -= delta;
      halves[0] -= (((halves[1] << 4) ^ (halves[1] >> 5)) + halves[1]) ^ (schedule + words[schedule & 3]);
    } else {
      halves[0] += (((halves[1] << 4) ^ (halves[1] >> 5)) + halves[1]) ^ (schedule + words[schedule & 3]);
      schedule += delta;
      halves[1] += (((halves[0] << 4) ^ (halves[0] >> 5)) + halves[0]) ^ (schedule + words[(schedule >> 11) & 3]);
    }
  }
  write_word(block, halves[0]);
  write_word(block + 4, halves[1]);
  clear_bytes(words, sizeof(words));
  clear_bytes(halves, sizeof(halves));
}

void xtea_encrypt_block(uint8_t block[XTEA_BLOCK_SIZE], const uint8_t key[XTEA_KEY_SIZE]) {
  transform_block(block, key, false);
}

void xtea_decrypt_block(uint8_t block[XTEA_BLOCK_SIZE], const uint8_t key[XTEA_KEY_SIZE]) {
  transform_block(block, key, true);
}

bool xtea_cbc_encrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  return cbc_encrypt(xtea_encrypt_block, XTEA_BLOCK_SIZE, key, iv, input, length, output, capacity, written);
}

bool xtea_cbc_decrypt(const uint8_t key[XTEA_KEY_SIZE], const uint8_t iv[XTEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  return cbc_decrypt(xtea_decrypt_block, XTEA_BLOCK_SIZE, key, iv, input, length, output, capacity, written);
}
