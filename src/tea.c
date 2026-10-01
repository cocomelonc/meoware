/* author: cocomelonc */
#include "tea.h"
#include <string.h>

/* Wheeler and Needham, TEA (1994):
 * https://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html */
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
      halves[1] -= ((halves[0] << 4) + words[2]) ^ (halves[0] + schedule) ^ ((halves[0] >> 5) + words[3]);
      halves[0] -= ((halves[1] << 4) + words[0]) ^ (halves[1] + schedule) ^ ((halves[1] >> 5) + words[1]);
      schedule -= delta;
    } else {
      schedule += delta;
      halves[0] += ((halves[1] << 4) + words[0]) ^ (halves[1] + schedule) ^ ((halves[1] >> 5) + words[1]);
      halves[1] += ((halves[0] << 4) + words[2]) ^ (halves[0] + schedule) ^ ((halves[0] >> 5) + words[3]);
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
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  uint8_t chain[TEA_BLOCK_SIZE];
  uint8_t block[TEA_BLOCK_SIZE];
  size_t offset, index;
  size_t padding = TEA_BLOCK_SIZE - length % TEA_BLOCK_SIZE;
  if (written == NULL) return false;
  *written = 0;
  if (key == NULL || iv == NULL || (input == NULL && length != 0) || output == NULL ||
      length > SIZE_MAX - padding || capacity < length + padding) return false;
  memcpy(chain, iv, sizeof(chain));
  for (offset = 0; offset < length + padding; offset += TEA_BLOCK_SIZE) {
    for (index = 0; index < TEA_BLOCK_SIZE; ++index) {
      uint8_t plain = offset + index < length ? input[offset + index] : (uint8_t)padding;
      block[index] = plain ^ chain[index];
    }
    tea_encrypt_block(block, key);
    memcpy(output + offset, block, sizeof(block));
    memcpy(chain, block, sizeof(chain));
  }
  *written = length + padding;
  clear_bytes(block, sizeof(block));
  clear_bytes(chain, sizeof(chain));
  return true;
}

bool tea_cbc_decrypt(const uint8_t key[TEA_KEY_SIZE], const uint8_t iv[TEA_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  uint8_t chain[TEA_BLOCK_SIZE], block[TEA_BLOCK_SIZE], saved[TEA_BLOCK_SIZE];
  size_t offset, index;
  unsigned int padding, invalid;
  if (written == NULL) return false;
  *written = 0;
  if (key == NULL || iv == NULL || input == NULL || output == NULL ||
      length == 0 || length % TEA_BLOCK_SIZE != 0 || capacity < length) return false;
  memcpy(chain, iv, sizeof(chain));
  for (offset = 0; offset < length; offset += TEA_BLOCK_SIZE) {
    memcpy(saved, input + offset, sizeof(saved));
    memcpy(block, saved, sizeof(block));
    tea_decrypt_block(block, key);
    for (index = 0; index < TEA_BLOCK_SIZE; ++index) output[offset + index] = block[index] ^ chain[index];
    memcpy(chain, saved, sizeof(chain));
  }
  padding = output[length - 1];
  invalid = padding == 0 || padding > TEA_BLOCK_SIZE;
  for (index = 0; index < TEA_BLOCK_SIZE; ++index) {
    if (index < padding && output[length - 1 - index] != padding) invalid = 1;
  }
  clear_bytes(chain, sizeof(chain));
  clear_bytes(block, sizeof(block));
  clear_bytes(saved, sizeof(saved));
  if (invalid) {
    clear_bytes(output, length);
    return false;
  }
  *written = length - padding;
  clear_bytes(output + *written, padding);
  return true;
}
