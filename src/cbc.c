/* author: cocomelonc */
#include "cbc.h"
#include <string.h>

static void clear_bytes(void *data, size_t length) {
  volatile uint8_t *cursor = data;
  while (length-- != 0) *cursor++ = 0;
}

bool cbc_encrypt(CbcBlockTransform transform, size_t block_size, const uint8_t *key,
                 const uint8_t *iv, const uint8_t *input, size_t length, uint8_t *output,
                 size_t capacity, size_t *written) {
  uint8_t chain[CBC_MAX_BLOCK_SIZE], block[CBC_MAX_BLOCK_SIZE];
  size_t offset, index, padding;
  if (written == NULL) return false;
  *written = 0;
  if (block_size != 8 && block_size != 16) return false;
  padding = block_size - length % block_size;
  if (transform == NULL || key == NULL || iv == NULL || (input == NULL && length != 0) ||
      output == NULL || length > SIZE_MAX - padding || capacity < length + padding)
    return false;
  memcpy(chain, iv, block_size);
  for (offset = 0; offset < length + padding; offset += block_size) {
    for (index = 0; index < block_size; ++index) {
      uint8_t plain = offset + index < length ? input[offset + index] : (uint8_t)padding;
      block[index] = plain ^ chain[index];
    }
    transform(block, key);
    memcpy(output + offset, block, block_size);
    memcpy(chain, block, block_size);
  }
  *written = length + padding;
  clear_bytes(block, sizeof(block));
  clear_bytes(chain, sizeof(chain));
  return true;
}

bool cbc_decrypt(CbcBlockTransform transform, size_t block_size, const uint8_t *key,
                 const uint8_t *iv, const uint8_t *input, size_t length, uint8_t *output,
                 size_t capacity, size_t *written) {
  uint8_t chain[CBC_MAX_BLOCK_SIZE], block[CBC_MAX_BLOCK_SIZE], saved[CBC_MAX_BLOCK_SIZE];
  size_t offset, index;
  unsigned int padding, invalid;
  if (written == NULL) return false;
  *written = 0;
  if (block_size != 8 && block_size != 16) return false;
  if (transform == NULL || key == NULL || iv == NULL || input == NULL || output == NULL ||
      length == 0 || length % block_size != 0 || capacity < length)
    return false;
  memcpy(chain, iv, block_size);
  for (offset = 0; offset < length; offset += block_size) {
    memcpy(saved, input + offset, block_size);
    memcpy(block, saved, block_size);
    transform(block, key);
    for (index = 0; index < block_size; ++index)
      output[offset + index] = block[index] ^ chain[index];
    memcpy(chain, saved, block_size);
  }
  padding = output[length - 1];
  invalid = padding == 0 || padding > block_size;
  for (index = 0; index < block_size; ++index) {
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
