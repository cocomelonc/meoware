/* author: cocomelonc */
#include "cbc64.h"
#include <string.h>

static void clear_bytes(void *data, size_t length) {
  volatile uint8_t *cursor = data;
  while (length-- != 0) *cursor++ = 0;
}

bool cbc64_encrypt(Cbc64BlockTransform transform, const uint8_t *key, const uint8_t iv[CBC64_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  uint8_t chain[CBC64_BLOCK_SIZE];
  uint8_t block[CBC64_BLOCK_SIZE];
  size_t offset, index;
  size_t padding = CBC64_BLOCK_SIZE - length % CBC64_BLOCK_SIZE;
  if (written == NULL) return false;
  *written = 0;
  if (transform == NULL || key == NULL || iv == NULL || (input == NULL && length != 0) || output == NULL ||
      length > SIZE_MAX - padding || capacity < length + padding) return false;
  memcpy(chain, iv, sizeof(chain));
  for (offset = 0; offset < length + padding; offset += CBC64_BLOCK_SIZE) {
    for (index = 0; index < CBC64_BLOCK_SIZE; ++index) {
      uint8_t plain = offset + index < length ? input[offset + index] : (uint8_t)padding;
      block[index] = plain ^ chain[index];
    }
    transform(block, key);
    memcpy(output + offset, block, sizeof(block));
    memcpy(chain, block, sizeof(chain));
  }
  *written = length + padding;
  clear_bytes(block, sizeof(block));
  clear_bytes(chain, sizeof(chain));
  return true;
}

bool cbc64_decrypt(Cbc64BlockTransform transform, const uint8_t *key, const uint8_t iv[CBC64_BLOCK_SIZE],
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  uint8_t chain[CBC64_BLOCK_SIZE], block[CBC64_BLOCK_SIZE], saved[CBC64_BLOCK_SIZE];
  size_t offset, index;
  unsigned int padding, invalid;
  if (written == NULL) return false;
  *written = 0;
  if (transform == NULL || key == NULL || iv == NULL || input == NULL || output == NULL ||
      length == 0 || length % CBC64_BLOCK_SIZE != 0 || capacity < length) return false;
  memcpy(chain, iv, sizeof(chain));
  for (offset = 0; offset < length; offset += CBC64_BLOCK_SIZE) {
    memcpy(saved, input + offset, sizeof(saved));
    memcpy(block, saved, sizeof(block));
    transform(block, key);
    for (index = 0; index < CBC64_BLOCK_SIZE; ++index) output[offset + index] = block[index] ^ chain[index];
    memcpy(chain, saved, sizeof(chain));
  }
  padding = output[length - 1];
  invalid = padding == 0 || padding > CBC64_BLOCK_SIZE;
  for (index = 0; index < CBC64_BLOCK_SIZE; ++index) {
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
