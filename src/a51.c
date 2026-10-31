/* author: cocomelonc */
#include "a51.h"
#include <string.h>

/* Three LFSRs, lengths 19/22/23, with majority-controlled clocking. */
static void clock_registers(uint32_t state[3], bool all) {
  unsigned int x = (state[0] >> 8) & 1;
  unsigned int y = (state[1] >> 10) & 1;
  unsigned int z = (state[2] >> 10) & 1;
  unsigned int majority = (x & y) | (z & (x | y));
  if (all || x == majority) {
    uint32_t feedback = (state[0] >> 13) ^ (state[0] >> 16) ^ (state[0] >> 17) ^ (state[0] >> 18);
    state[0] = ((state[0] << 1) | (feedback & 1)) & UINT32_C(0x7ffff);
  }
  if (all || y == majority) {
    uint32_t feedback = (state[1] >> 20) ^ (state[1] >> 21);
    state[1] = ((state[1] << 1) | (feedback & 1)) & UINT32_C(0x3fffff);
  }
  if (all || z == majority) {
    uint32_t feedback = (state[2] >> 7) ^ (state[2] >> 20) ^ (state[2] >> 21) ^ (state[2] >> 22);
    state[2] = ((state[2] << 1) | (feedback & 1)) & UINT32_C(0x7fffff);
  }
}

bool a51_stream_init(A51Stream *stream, const uint8_t key[A51_KEY_SIZE], uint32_t frame) {
  if (stream == NULL || key == NULL || frame > A51_FRAME_MASK) return false;
  memset(stream, 0, sizeof(*stream));
  for (unsigned int bit = 0; bit < 86; ++bit) {
    unsigned int incoming = bit < 64 ? (key[bit / 8] >> (bit % 8)) & 1 : (frame >> (bit - 64)) & 1;
    clock_registers(stream->state, true);
    for (unsigned int i = 0; i < 3; ++i) stream->state[i] ^= incoming;
  }
  for (unsigned int i = 0; i < 100; ++i) clock_registers(stream->state, false);
  stream->initialized = true;
  return true;
}

bool a51_stream_crypt(A51Stream *stream, const uint8_t *input, size_t length, uint8_t *output,
                      size_t capacity, size_t *written) {
  if (written == NULL) return false;
  *written = 0;
  if (stream == NULL || !stream->initialized || (input == NULL && length) || output == NULL ||
      capacity < length)
    return false;
  for (size_t i = 0; i < length; ++i) {
    uint8_t key_byte = 0;
    for (unsigned int bit = 0; bit < 8; ++bit) {
      clock_registers(stream->state, false);
      unsigned int next = (stream->state[0] >> 18) ^ (stream->state[1] >> 21) ^
                          (stream->state[2] >> 22);
      key_byte = (uint8_t)((key_byte << 1) | next);
    }
    output[i] = input[i] ^ key_byte;
  }
  *written = length;
  return true;
}

void a51_stream_close(A51Stream *stream) {
  if (stream == NULL) return;
  volatile uint32_t *clear = stream->state;
  for (unsigned int i = 0; i < 3; ++i) clear[i] = 0;
  stream->initialized = false;
}

bool a51_crypt(const uint8_t key[A51_KEY_SIZE], uint32_t frame, const uint8_t *input, size_t length,
               uint8_t *output, size_t capacity, size_t *written) {
  A51Stream stream;
  bool success;
  if (written == NULL) return false;
  *written = 0;
  if (!a51_stream_init(&stream, key, frame)) return false;
  success = a51_stream_crypt(&stream, input, length, output, capacity, written);
  a51_stream_close(&stream);
  return success;
}
