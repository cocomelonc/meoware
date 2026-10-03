/* author: cocomelonc */
#include "a51.h"

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

bool a51_crypt(const uint8_t key[A51_KEY_SIZE], uint32_t frame,
  const uint8_t *input, size_t length, uint8_t *output, size_t capacity, size_t *written) {
  uint32_t state[3] = { 0 };
  if (!written) return false;
  *written = 0;
  if (!key || frame > A51_FRAME_MASK || (!input && length) || !output || capacity < length) return false;
  for (unsigned int bit = 0; bit < 86; ++bit) {
    unsigned int incoming = bit < 64 ? (key[bit / 8] >> (bit % 8)) & 1 : (frame >> (bit - 64)) & 1;
    clock_registers(state, true);
    for (unsigned int i = 0; i < 3; ++i) state[i] ^= incoming;
  }
  for (unsigned int i = 0; i < 100; ++i) clock_registers(state, false);
  for (size_t i = 0; i < length; ++i) {
    uint8_t stream = 0;
    for (unsigned int bit = 0; bit < 8; ++bit) {
      clock_registers(state, false);
      unsigned int next = (state[0] >> 18) ^ (state[1] >> 21) ^ (state[2] >> 22);
      stream = (uint8_t)((stream << 1) | next);
    }
    output[i] = input[i] ^ stream;
  }
  volatile uint32_t *clear = state;
  for (unsigned int i = 0; i < 3; ++i) clear[i] = 0;
  *written = length;
  return true;
}
