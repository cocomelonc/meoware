/* author: cocomelonc */
#include "feal8.h"
#include "cbc.h"

/* Algorithm references, rather than the simplified mixing example in blog #32:
 * Handbook of Applied Cryptography, section 7.5, algorithms 7.94/7.95,
 * table 7.9 and note 7.96: https://cacr.uwaterloo.ca/hac/about/chap7.pdf
 * NTT's definitions of f, fK and S:
 * https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf
 * Historical cipher, included for educational lab experiments.
 */

static void clear_bytes(void *data, size_t length) {
  volatile uint8_t *cursor = data;
  while (length-- != 0) *cursor++ = 0;
}

static uint32_t read_word(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void write_word(uint8_t *bytes, uint32_t word) {
  bytes[0] = (uint8_t)(word >> 24);
  bytes[1] = (uint8_t)(word >> 16);
  bytes[2] = (uint8_t)(word >> 8);
  bytes[3] = (uint8_t)word;
}

static uint8_t substitute(uint8_t left, uint8_t right, unsigned int carry) {
  uint8_t sum = (uint8_t)((unsigned int)left + right + carry);
  return (uint8_t)((sum << 2) | (sum >> 6));
}

static uint32_t pack(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

static uint32_t round_function(uint32_t input, const uint8_t subkey[2]) {
  uint8_t a = (uint8_t)(input >> 24), b = (uint8_t)(input >> 16);
  uint8_t c = (uint8_t)(input >> 8), d = (uint8_t)input;
  uint8_t left = a ^ b ^ subkey[0], right = c ^ d ^ subkey[1];
  uint8_t middle_left = substitute(left, right, 1);
  uint8_t middle_right = substitute(right, middle_left, 0);
  return pack(substitute(a, middle_left, 0), middle_left, middle_right,
              substitute(d, middle_right, 1));
}

static uint32_t key_function(uint32_t input, uint32_t other) {
  uint8_t a = (uint8_t)(input >> 24), b = (uint8_t)(input >> 16);
  uint8_t c = (uint8_t)(input >> 8), d = (uint8_t)input;
  uint8_t left = a ^ b, right = c ^ d;
  uint8_t middle_left = substitute(left, right ^ (uint8_t)(other >> 24), 1);
  uint8_t middle_right = substitute(right, middle_left ^ (uint8_t)(other >> 16), 0);
  return pack(substitute(a, middle_left ^ (uint8_t)(other >> 8), 0),
              middle_left, middle_right, substitute(d, middle_right ^ (uint8_t)other, 1));
}

void feal8_expand_key(const uint8_t key[FEAL8_KEY_SIZE], uint8_t schedule[FEAL8_SCHEDULE_SIZE]) {
  uint32_t history[3] = {0, read_word(key), read_word(key + 4)};
  for (unsigned int step = 0; step < FEAL8_SCHEDULE_SIZE / 4U; ++step) {
    uint32_t next = key_function(history[1], history[2] ^ history[0]);
    write_word(schedule + 4U * step, next);
    history[0] = history[1];
    history[1] = history[2];
    history[2] = next;
  }
  clear_bytes(history, sizeof(history));
}

static void transform(uint8_t block[FEAL8_BLOCK_SIZE],
                      const uint8_t schedule[FEAL8_SCHEDULE_SIZE], bool reverse) {
  const uint8_t *initial = schedule + (reverse ? 24U : 16U);
  const uint8_t *final = schedule + (reverse ? 16U : 24U);
  uint32_t state[2] = {read_word(block) ^ read_word(initial),
                       read_word(block + 4) ^ read_word(initial + 4)};
  state[1] ^= state[0];
  for (unsigned int step = 0; step < FEAL8_ROUNDS; ++step) {
    unsigned int round = reverse ? FEAL8_ROUNDS - 1U - step : step;
    uint32_t next = state[0] ^ round_function(state[1], schedule + 2U * round);
    state[0] = state[1];
    state[1] = next;
  }
  state[0] ^= state[1];
  write_word(block, state[1] ^ read_word(final));
  write_word(block + 4, state[0] ^ read_word(final + 4));
  clear_bytes(state, sizeof(state));
}

void feal8_encrypt_prepared(uint8_t block[FEAL8_BLOCK_SIZE],
                            const uint8_t schedule[FEAL8_SCHEDULE_SIZE]) {
  transform(block, schedule, false);
}

void feal8_decrypt_prepared(uint8_t block[FEAL8_BLOCK_SIZE],
                            const uint8_t schedule[FEAL8_SCHEDULE_SIZE]) {
  transform(block, schedule, true);
}

static void crypt_block(uint8_t block[FEAL8_BLOCK_SIZE], const uint8_t key[FEAL8_KEY_SIZE],
                         bool encrypt) {
  uint8_t schedule[FEAL8_SCHEDULE_SIZE];
  feal8_expand_key(key, schedule);
  transform(block, schedule, !encrypt);
  clear_bytes(schedule, sizeof(schedule));
}

void feal8_encrypt_block(uint8_t block[FEAL8_BLOCK_SIZE], const uint8_t key[FEAL8_KEY_SIZE]) {
  crypt_block(block, key, true);
}

void feal8_decrypt_block(uint8_t block[FEAL8_BLOCK_SIZE], const uint8_t key[FEAL8_KEY_SIZE]) {
  crypt_block(block, key, false);
}

static bool crypt_cbc(bool encrypt, const uint8_t *key, const uint8_t *iv,
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  uint8_t schedule[FEAL8_SCHEDULE_SIZE];
  bool success;
  if (written != NULL) *written = 0;
  if (key == NULL || written == NULL) return false;
  feal8_expand_key(key, schedule);
  success = encrypt ? cbc_encrypt(feal8_encrypt_prepared, FEAL8_BLOCK_SIZE, schedule, iv,
                                  input, length, output, capacity, written)
                    : cbc_decrypt(feal8_decrypt_prepared, FEAL8_BLOCK_SIZE, schedule, iv,
                                  input, length, output, capacity, written);
  clear_bytes(schedule, sizeof(schedule));
  return success;
}

bool feal8_cbc_encrypt(const uint8_t key[FEAL8_KEY_SIZE], const uint8_t iv[FEAL8_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  return crypt_cbc(true, key, iv, input, length, output, capacity, written);
}

bool feal8_cbc_decrypt(const uint8_t key[FEAL8_KEY_SIZE], const uint8_t iv[FEAL8_BLOCK_SIZE],
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity,
                       size_t *written) {
  return crypt_cbc(false, key, iv, input, length, output, capacity, written);
}
