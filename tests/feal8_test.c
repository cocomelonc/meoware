/* author: cocomelonc */
#include "feal8.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void known_answers(void) {
  /* HAC example 7.99 publishes both the full expanded key and ciphertext.
   * https://cacr.uwaterloo.ca/hac/about/chap7.pdf, pages 261-262.
   * The original key and byte order are intentionally asymmetric. */
  const uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  const uint8_t expected[8] = {0xce, 0xef, 0x2c, 0x86, 0xf2, 0x49, 0x07, 0x52};
  const uint8_t expanded[32] = {
      0xdf, 0x3b, 0xca, 0x36, 0xf1, 0x7c, 0x1a, 0xec,
      0x45, 0xa5, 0xb9, 0xc7, 0x26, 0xeb, 0xad, 0x25,
      0x8b, 0x2a, 0xec, 0xb7, 0xac, 0x50, 0x9d, 0x4c,
      0x22, 0xcd, 0x47, 0x9b, 0xa8, 0xd5, 0x0c, 0xb5};
  uint8_t unaligned_key[10], block[10], schedule[FEAL8_SCHEDULE_SIZE + 2];
  memset(unaligned_key, 0xa5, sizeof(unaligned_key));
  memcpy(unaligned_key + 1, key, sizeof(key));
  memset(block, 0, sizeof(block));
  block[0] = 0xa5;
  block[9] = 0x5a;
  memset(schedule, 0xa5, sizeof(schedule));
  feal8_expand_key(unaligned_key + 1, schedule + 1);
  assert(memcmp(schedule + 1, expanded, sizeof(expanded)) == 0);
  feal8_encrypt_prepared(block + 1, schedule + 1);
  assert(memcmp(block + 1, expected, sizeof(expected)) == 0);
  /* Decrypt the published ciphertext independently of the encryption result. */
  memcpy(block + 1, expected, sizeof(expected));
  feal8_decrypt_prepared(block + 1, schedule + 1);
  for (size_t i = 1; i <= 8; ++i) assert(block[i] == 0);
  feal8_encrypt_block(block + 1, unaligned_key + 1);
  assert(memcmp(block + 1, expected, sizeof(expected)) == 0);
  feal8_decrypt_block(block + 1, unaligned_key + 1);
  for (size_t i = 1; i <= 8; ++i) assert(block[i] == 0);
  assert(block[0] == 0xa5 && block[9] == 0x5a);
  assert(unaligned_key[0] == 0xa5 && unaligned_key[9] == 0xa5);
  assert(memcmp(unaligned_key + 1, key, sizeof(key)) == 0);
  assert(schedule[0] == 0xa5 && schedule[sizeof(schedule) - 1] == 0xa5);
  assert(memcmp(schedule + 1, expanded, sizeof(expanded)) == 0);

  /* NTT specification section 5.2: fK(0,0) = 10041044. With a zero
   * key, the first four bytes emitted by the key schedule equal that value.
   * https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf */
  const uint8_t zero[8] = {0}, first_subkeys[4] = {0x10, 0x04, 0x10, 0x44};
  feal8_expand_key(zero, schedule + 1);
  assert(memcmp(schedule + 1, first_subkeys, sizeof(first_subkeys)) == 0);

  /* CBC chaining oracle: IV=0, P1=0, P2=C implies C1=C2=published C. */
  uint8_t input[16] = {0}, encrypted[24], restored[24];
  size_t written;
  memcpy(input + 8, expected, 8);
  assert(feal8_cbc_encrypt(key, zero, input, sizeof(input), encrypted, sizeof(encrypted), &written));
  assert(written == 24 && memcmp(encrypted, expected, 8) == 0 &&
         memcmp(encrypted + 8, expected, 8) == 0);
  assert(feal8_cbc_decrypt(key, zero, encrypted, written, restored, sizeof(restored), &written));
  assert(written == sizeof(input) && memcmp(restored, input, written) == 0);
}

static void round_trip(const uint8_t *plain, size_t length) {
  uint8_t key[8], iv[8], saved_iv[8];
  uint8_t encrypted[131088], restored[131088];
  size_t written, recovered;
  for (size_t i = 0; i < 8; ++i) {
    key[i] = (uint8_t)(length * 17 + i * 29);
    iv[i] = (uint8_t)(length + i * 31);
  }
  memcpy(saved_iv, iv, sizeof(iv));
  assert(feal8_cbc_encrypt(key, iv, plain, length, encrypted, sizeof(encrypted), &written));
  assert(written == length + 8 - length % 8);
  assert(feal8_cbc_decrypt(key, iv, encrypted, written, restored, sizeof(restored), &recovered));
  assert(recovered == length && memcmp(plain, restored, length) == 0);
  assert(feal8_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &recovered));
  assert(recovered == written && memcmp(restored, encrypted, written) == 0);
  assert(feal8_cbc_decrypt(key, iv, restored, written, restored, sizeof(restored), &recovered));
  assert(recovered == length && memcmp(plain, restored, length) == 0);
  assert(memcmp(iv, saved_iv, sizeof(iv)) == 0);
  iv[0] ^= 1;
  assert(feal8_cbc_encrypt(key, iv, plain, length, restored, sizeof(restored), &recovered));
  assert(memcmp(restored, encrypted, written) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[8] = {0}, iv[8] = {0}, block[8], output[16];
  size_t written = 99;
  assert(!feal8_cbc_encrypt(NULL, iv, NULL, 0, output, sizeof(output), &written) && written == 0);
  assert(!feal8_cbc_decrypt(NULL, iv, output, 8, output, sizeof(output), &written));
  assert(!feal8_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), NULL));
  assert(!feal8_cbc_encrypt(key, NULL, NULL, 0, output, sizeof(output), &written));
  assert(!feal8_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(!feal8_cbc_encrypt(key, iv, NULL, 0, NULL, sizeof(output), &written));
  memset(output, 0xa5, sizeof(output));
  assert(!feal8_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!feal8_cbc_encrypt(key, iv, NULL, 0, output, 7, &written));
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
  assert(feal8_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), &written) && written == 8);
  assert(!feal8_cbc_decrypt(key, iv, output, 0, output, sizeof(output), &written));
  assert(!feal8_cbc_decrypt(key, iv, output, 7, output, sizeof(output), &written));
  assert(!feal8_cbc_decrypt(key, iv, output, 8, output, 7, &written));
  assert(feal8_cbc_decrypt(key, iv, output, 8, output, sizeof(output), &written) && written == 0);
  for (unsigned int padding = 0; padding < 256; ++padding) {
    if (padding == 1) continue;
    memset(block, 0, sizeof(block));
    block[7] = (uint8_t)padding;
    feal8_encrypt_block(block, key);
    assert(!feal8_cbc_decrypt(key, iv, block, sizeof(block), output, sizeof(output), &written));
    assert(written == 0);
    for (size_t i = 0; i < 8; ++i) assert(output[i] == 0);
  }
}

static uint8_t next_byte(uint32_t *state) {
  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;
  return (uint8_t)*state;
}

static void varied_blocks(void) {
  uint32_t state = UINT32_C(0x4821cdab);
  for (unsigned int trial = 0; trial < 1024; ++trial) {
    uint8_t key[8], plain[8], block[8], schedule[FEAL8_SCHEDULE_SIZE];
    for (unsigned int i = 0; i < 8; ++i) {
      key[i] = next_byte(&state);
      plain[i] = next_byte(&state);
    }
    memcpy(block, plain, sizeof(block));
    feal8_expand_key(key, schedule);
    feal8_encrypt_prepared(block, schedule);
    feal8_decrypt_block(block, key);
    assert(memcmp(block, plain, sizeof(block)) == 0);
  }
}

int main(void) {
  uint8_t plain[131073];
  const size_t boundaries[] = {65535, 65536, 65537, 131073};
  known_answers();
  invalid_inputs();
  varied_blocks();
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i ^ (i >> 8));
  for (size_t length = 0; length <= 257; ++length) round_trip(plain, length);
  for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i)
    round_trip(plain, boundaries[i]);
  puts("FEAL-8: published ciphertext/subkeys, CBC, padding, guards, varied keys and large buffers passed.");
  return 0;
}
