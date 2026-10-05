/* author: cocomelonc */
#include "camellia.h"
#include "cbc.h"

/* Camellia-128 specification: https://www.rfc-editor.org/rfc/rfc3713 */
static const uint8_t sbox[256] = {
    112, 130, 44,  236, 179, 39,  192, 229, 228, 133, 87,  53,  234, 12,  174, 65,  35,  239, 107,
    147, 69,  25,  165, 33,  237, 14,  79,  78,  29,  101, 146, 189, 134, 184, 175, 143, 124, 235,
    31,  206, 62,  48,  220, 95,  94,  197, 11,  26,  166, 225, 57,  202, 213, 71,  93,  61,  217,
    1,   90,  214, 81,  86,  108, 77,  139, 13,  154, 102, 251, 204, 176, 45,  116, 18,  43,  32,
    240, 177, 132, 153, 223, 76,  203, 194, 52,  126, 118, 5,   109, 183, 169, 49,  209, 23,  4,
    215, 20,  88,  58,  97,  222, 27,  17,  28,  50,  15,  156, 22,  83,  24,  242, 34,  254, 68,
    207, 178, 195, 181, 122, 145, 36,  8,   232, 168, 96,  252, 105, 80,  170, 208, 160, 125, 161,
    137, 98,  151, 84,  91,  30,  149, 224, 255, 100, 210, 16,  196, 0,   72,  163, 247, 117, 219,
    138, 3,   230, 218, 9,   63,  221, 148, 135, 92,  131, 2,   205, 74,  144, 51,  115, 103, 246,
    243, 157, 127, 191, 226, 82,  155, 216, 38,  200, 55,  198, 59,  129, 150, 111, 75,  19,  190,
    99,  46,  233, 121, 167, 140, 159, 110, 188, 142, 41,  245, 249, 182, 47,  253, 180, 89,  120,
    152, 6,   106, 231, 70,  113, 186, 212, 37,  171, 66,  136, 162, 141, 250, 114, 7,   185, 85,
    248, 238, 172, 10,  54,  73,  42,  104, 60,  56,  241, 164, 64,  40,  211, 123, 187, 201, 67,
    193, 21,  227, 173, 244, 119, 199, 128, 158};

typedef struct {
  uint64_t whitening[4], rounds[CAMELLIA_ROUNDS], layers[4];
} Subkeys;

static uint64_t read_word(const uint8_t *bytes) {
  uint64_t word = 0;
  for (unsigned int i = 0; i < 8; ++i) word = (word << 8) | bytes[i];
  return word;
}

static void write_word(uint8_t *bytes, uint64_t word) {
  for (unsigned int i = 0; i < 8; ++i) bytes[i] = (uint8_t)(word >> (56 - 8 * i));
}

static void clear_bytes(void *data, size_t size) {
  volatile uint8_t *cursor = data;
  while (size-- != 0) *cursor++ = 0;
}

static uint8_t rotate_byte(uint8_t value, unsigned int count) {
  return (uint8_t)((value << count) | (value >> (8 - count)));
}

static uint64_t feistel(uint64_t word, uint64_t key) {
  uint8_t t[8], y[8];
  write_word(t, word ^ key);
  t[0] = sbox[t[0]];
  t[1] = rotate_byte(sbox[t[1]], 1);
  t[2] = rotate_byte(sbox[t[2]], 7);
  t[3] = sbox[rotate_byte(t[3], 1)];
  t[4] = rotate_byte(sbox[t[4]], 1);
  t[5] = rotate_byte(sbox[t[5]], 7);
  t[6] = sbox[rotate_byte(t[6], 1)];
  t[7] = sbox[t[7]];
  y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
  y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
  y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
  y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
  y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
  y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
  y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
  y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
  return read_word(y);
}

/* High half of a 128-bit rotation; adding 64 selects the low half. */
static uint64_t rotated_half(const uint64_t pair[2], unsigned int count) {
  uint64_t high = pair[(count / 64) & 1], low = pair[1 - ((count / 64) & 1)];
  count %= 64;
  return count == 0 ? high : (high << count) | (low >> (64 - count));
}

static void rotate_pair(uint64_t out[2], const uint64_t pair[2], unsigned int count) {
  out[0] = rotated_half(pair, count);
  out[1] = rotated_half(pair, count + 64);
}

static void expand_key(const uint8_t *key, Subkeys *keys) {
  uint64_t kl[2] = {read_word(key), read_word(key + 8)};
  uint64_t ka[2] = {kl[0], kl[1]};
  ka[1] ^= feistel(ka[0], UINT64_C(0xa09e667f3bcc908b));
  ka[0] ^= feistel(ka[1], UINT64_C(0xb67ae8584caa73b2));
  ka[0] ^= kl[0];
  ka[1] ^= kl[1];
  ka[1] ^= feistel(ka[0], UINT64_C(0xc6ef372fe94f82be));
  ka[0] ^= feistel(ka[1], UINT64_C(0x54ff53a5f1d36f1c));

  rotate_pair(keys->whitening, kl, 0);
  rotate_pair(keys->rounds, ka, 0);
  rotate_pair(keys->rounds + 2, kl, 15);
  rotate_pair(keys->rounds + 4, ka, 15);
  rotate_pair(keys->layers, ka, 30);
  rotate_pair(keys->rounds + 6, kl, 45);
  keys->rounds[8] = rotated_half(ka, 45);
  keys->rounds[9] = rotated_half(kl, 60 + 64);
  rotate_pair(keys->rounds + 10, ka, 60);
  rotate_pair(keys->layers + 2, kl, 77);
  rotate_pair(keys->rounds + 12, kl, 94);
  rotate_pair(keys->rounds + 14, ka, 94);
  rotate_pair(keys->rounds + 16, kl, 111);
  rotate_pair(keys->whitening + 2, ka, 111);
  clear_bytes(kl, sizeof(kl));
  clear_bytes(ka, sizeof(ka));
}

static uint64_t fl(uint64_t word, uint64_t key, bool reverse) {
  uint32_t high = (uint32_t)(word >> 32), low = (uint32_t)word;
  if (reverse) high ^= low | (uint32_t)key;
  uint32_t masked = high & (uint32_t)(key >> 32);
  low ^= (masked << 1) | (masked >> 31);
  if (!reverse) high ^= low | (uint32_t)key;
  return ((uint64_t)high << 32) | low;
}

static void transform_block(uint8_t *block, const uint8_t *key, bool reverse) {
  Subkeys keys;
  expand_key(key, &keys);
  unsigned int before = reverse ? 2 : 0, after = reverse ? 0 : 2;
  uint64_t left = read_word(block) ^ keys.whitening[before];
  uint64_t right = read_word(block + 8) ^ keys.whitening[before + 1];
  for (unsigned int round = 0; round < CAMELLIA_ROUNDS; ++round) {
    uint64_t subkey = keys.rounds[reverse ? CAMELLIA_ROUNDS - 1 - round : round];
    if ((round & 1) == 0)
      right ^= feistel(left, subkey);
    else
      left ^= feistel(right, subkey);
    if (round == 5 || round == 11) {
      unsigned int layer = round == 5 ? 0 : 2;
      left = fl(left, keys.layers[reverse ? 3 - layer : layer], false);
      right = fl(right, keys.layers[reverse ? 2 - layer : layer + 1], true);
    }
  }
  write_word(block, right ^ keys.whitening[after]);
  write_word(block + 8, left ^ keys.whitening[after + 1]);
  clear_bytes(&keys, sizeof(keys));
}

void camellia_encrypt_block(uint8_t block[CAMELLIA_BLOCK_SIZE],
                            const uint8_t key[CAMELLIA_KEY_SIZE]) {
  transform_block(block, key, false);
}

void camellia_decrypt_block(uint8_t block[CAMELLIA_BLOCK_SIZE],
                            const uint8_t key[CAMELLIA_KEY_SIZE]) {
  transform_block(block, key, true);
}

bool camellia_cbc_encrypt(const uint8_t key[CAMELLIA_KEY_SIZE],
                          const uint8_t iv[CAMELLIA_BLOCK_SIZE], const uint8_t *input,
                          size_t length, uint8_t *output, size_t capacity, size_t *written) {
  return cbc_encrypt(camellia_encrypt_block, CAMELLIA_BLOCK_SIZE, key, iv, input, length, output,
                     capacity, written);
}

bool camellia_cbc_decrypt(const uint8_t key[CAMELLIA_KEY_SIZE],
                          const uint8_t iv[CAMELLIA_BLOCK_SIZE], const uint8_t *input,
                          size_t length, uint8_t *output, size_t capacity, size_t *written) {
  return cbc_decrypt(camellia_decrypt_block, CAMELLIA_BLOCK_SIZE, key, iv, input, length, output,
                     capacity, written);
}
