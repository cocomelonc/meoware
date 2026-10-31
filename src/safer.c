/* author: cocomelonc */
#include "safer.h"
#include "cbc.h"
#include <string.h>

/* Algorithm reference: Richard De Moliner's SAFER implementation, as maintained
 * by LibTomCrypt (Unlicense):
 * https://github.com/libtom/libtomcrypt/blob/develop/src/ciphers/safer/safer.c
 * These immutable tables are generated from E(i) = 45^i mod 257 (256 -> 0);
 * L(E(i)) = i. No mutable global initialization or secret-dependent allocation.
 */
static const uint8_t exponent[256] = {
      1,  45, 226, 147, 190,  69,  21, 174, 120,   3, 135, 164, 184,  56, 207,  63,
      8, 103,   9, 148, 235,  38, 168, 107, 189,  24,  52,  27, 187, 191, 114, 247,
     64,  53,  72, 156,  81,  47,  59,  85, 227, 192, 159, 216, 211, 243, 141, 177,
    255, 167,  62, 220, 134, 119, 215, 166,  17, 251, 244, 186, 146, 145, 100, 131,
    241,  51, 239, 218,  44, 181, 178,  43, 136, 209, 153, 203, 140, 132,  29,  20,
    129, 151, 113, 202,  95, 163, 139,  87,  60, 130, 196,  82,  92,  28, 232, 160,
      4, 180, 133,  74, 246,  19,  84, 182, 223,  12,  26, 142, 222, 224,  57, 252,
     32, 155,  36,  78, 169, 152, 158, 171, 242,  96, 208, 108, 234, 250, 199, 217,
      0, 212,  31, 110,  67, 188, 236,  83, 137, 254, 122,  93,  73, 201,  50, 194,
    249, 154, 248, 109,  22, 219,  89, 150,  68, 233, 205, 230,  70,  66, 143,  10,
    193, 204, 185, 101, 176, 210, 198, 172,  30,  65,  98,  41,  46,  14, 116,  80,
      2,  90, 195,  37, 123, 138,  42,  91, 240,   6,  13,  71, 111, 112, 157, 126,
     16, 206,  18,  39, 213,  76,  79, 214, 121,  48, 104,  54, 117, 125, 228, 237,
    128, 106, 144,  55, 162,  94, 118, 170, 197, 127,  61, 175, 165, 229,  25,  97,
    253,  77, 124, 183,  11, 238, 173,  75,  34, 245, 231, 115,  35,  33, 200,   5,
    225, 102, 221, 179,  88, 105,  99,  86,  15, 161,  49, 149,  23,   7,  58,  40};

static const uint8_t logarithm[256] = {
    128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248,
    192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130,
    112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37,
    201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15,
     32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198,
    175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84,
    121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188,
    189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217,
    208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158,
    210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42,
     95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219,
    164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29,
     41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14,
    122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104,
    109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66,
    184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48};

static void clear_bytes(void *data, size_t length) {
  volatile uint8_t *cursor = data;
  while (length-- != 0) *cursor++ = 0;
}

static uint8_t rotate_byte(uint8_t value, unsigned int count) {
  count &= 7U;
  return count == 0 ? value : (uint8_t)((value << count) | (value >> (8U - count)));
}

static bool xor_position(unsigned int index) {
  return index == 0 || index == 3 || index == 4 || index == 7;
}

void safer_expand_key(const uint8_t key[SAFER_KEY_SIZE], uint8_t schedule[SAFER_SCHEDULE_SIZE]) {
  memcpy(schedule, key, SAFER_KEY_SIZE);
  for (unsigned int round = 1; round <= SAFER_ROUNDS; ++round) {
    for (unsigned int byte = 0; byte < SAFER_KEY_SIZE; ++byte) {
      schedule[(2U * round - 1U) * SAFER_BLOCK_SIZE + byte] =
          (uint8_t)(rotate_byte(key[byte], 5U + 6U * round) +
                    exponent[exponent[18U * round + byte + 1U]]);
      schedule[2U * round * SAFER_BLOCK_SIZE + byte] =
          (uint8_t)(rotate_byte(key[byte], 6U * round) +
                    exponent[exponent[18U * round + byte + 10U]]);
    }
  }
}

static void mix(uint8_t state[SAFER_BLOCK_SIZE], unsigned int stride, bool reverse) {
  for (unsigned int base = 0; base < SAFER_BLOCK_SIZE; base += 2U * stride) {
    for (unsigned int offset = 0; offset < stride; ++offset) {
      uint8_t *left = &state[base + offset], *right = &state[base + offset + stride];
      if (reverse) {
        *left = (uint8_t)(*left - *right);
        *right = (uint8_t)(*right - *left);
      } else {
        *right = (uint8_t)(*right + *left);
        *left = (uint8_t)(*left + *right);
      }
    }
  }
}

static void transform(uint8_t block[SAFER_BLOCK_SIZE],
                      const uint8_t schedule[SAFER_SCHEDULE_SIZE], bool reverse) {
  static const unsigned int permutation[2][8] = {
      {0, 4, 1, 5, 2, 6, 3, 7}, {0, 2, 4, 6, 1, 3, 5, 7}};
  uint8_t state[SAFER_BLOCK_SIZE], permuted[SAFER_BLOCK_SIZE];
  const uint8_t *last = schedule + 2U * SAFER_ROUNDS * SAFER_BLOCK_SIZE;
  memcpy(state, block, sizeof(state));

  if (reverse) {
    for (unsigned int byte = 0; byte < SAFER_BLOCK_SIZE; ++byte)
      state[byte] = xor_position(byte) ? state[byte] ^ last[byte]
                                       : (uint8_t)(state[byte] - last[byte]);
  }

  for (unsigned int step = 0; step < SAFER_ROUNDS; ++step) {
    unsigned int round = reverse ? SAFER_ROUNDS - 1U - step : step;
    const uint8_t *first = schedule + 2U * round * SAFER_BLOCK_SIZE;
    const uint8_t *second = first + SAFER_BLOCK_SIZE;
    if (reverse) {
      for (unsigned int byte = 0; byte < SAFER_BLOCK_SIZE; ++byte)
        permuted[byte] = state[permutation[1][byte]];
      memcpy(state, permuted, sizeof(state));
      mix(state, 4, true);
      mix(state, 2, true);
      mix(state, 1, true);
    }
    for (unsigned int byte = 0; byte < SAFER_BLOCK_SIZE; ++byte) {
      if (reverse) {
        state[byte] = xor_position(byte)
            ? logarithm[(uint8_t)(state[byte] - second[byte])] ^ first[byte]
            : (uint8_t)(exponent[state[byte] ^ second[byte]] - first[byte]);
      } else {
        uint8_t mixed = xor_position(byte) ? state[byte] ^ first[byte]
                                           : (uint8_t)(state[byte] + first[byte]);
        state[byte] = xor_position(byte) ? (uint8_t)(exponent[mixed] + second[byte])
                                         : logarithm[mixed] ^ second[byte];
      }
    }
    if (!reverse) {
      mix(state, 1, false);
      mix(state, 2, false);
      mix(state, 4, false);
      for (unsigned int byte = 0; byte < SAFER_BLOCK_SIZE; ++byte)
        permuted[byte] = state[permutation[0][byte]];
      memcpy(state, permuted, sizeof(state));
    }
  }
  if (!reverse) {
    for (unsigned int byte = 0; byte < SAFER_BLOCK_SIZE; ++byte)
      state[byte] = xor_position(byte) ? state[byte] ^ last[byte]
                                       : (uint8_t)(state[byte] + last[byte]);
  }
  memcpy(block, state, sizeof(state));
  clear_bytes(state, sizeof(state));
  clear_bytes(permuted, sizeof(permuted));
}

void safer_encrypt_prepared(uint8_t block[SAFER_BLOCK_SIZE],
                            const uint8_t schedule[SAFER_SCHEDULE_SIZE]) {
  transform(block, schedule, false);
}

void safer_decrypt_prepared(uint8_t block[SAFER_BLOCK_SIZE],
                            const uint8_t schedule[SAFER_SCHEDULE_SIZE]) {
  transform(block, schedule, true);
}

void safer_encrypt_block(uint8_t block[SAFER_BLOCK_SIZE], const uint8_t key[SAFER_KEY_SIZE]) {
  uint8_t schedule[SAFER_SCHEDULE_SIZE];
  safer_expand_key(key, schedule);
  safer_encrypt_prepared(block, schedule);
  clear_bytes(schedule, sizeof(schedule));
}

void safer_decrypt_block(uint8_t block[SAFER_BLOCK_SIZE], const uint8_t key[SAFER_KEY_SIZE]) {
  uint8_t schedule[SAFER_SCHEDULE_SIZE];
  safer_expand_key(key, schedule);
  safer_decrypt_prepared(block, schedule);
  clear_bytes(schedule, sizeof(schedule));
}

static bool crypt_cbc(bool encrypt, const uint8_t *key, const uint8_t *iv,
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  uint8_t schedule[SAFER_SCHEDULE_SIZE];
  bool success;
  if (written != NULL) *written = 0;
  if (key == NULL || written == NULL) return false;
  safer_expand_key(key, schedule);
  success = encrypt ? cbc_encrypt(safer_encrypt_prepared, SAFER_BLOCK_SIZE, schedule, iv,
                                  input, length, output, capacity, written)
                    : cbc_decrypt(safer_decrypt_prepared, SAFER_BLOCK_SIZE, schedule, iv,
                                  input, length, output, capacity, written);
  clear_bytes(schedule, sizeof(schedule));
  return success;
}

bool safer_cbc_encrypt(const uint8_t key[SAFER_KEY_SIZE], const uint8_t iv[SAFER_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  return crypt_cbc(true, key, iv, input, length, output, capacity, written);
}

bool safer_cbc_decrypt(const uint8_t key[SAFER_KEY_SIZE], const uint8_t iv[SAFER_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  return crypt_cbc(false, key, iv, input, length, output, capacity, written);
}

