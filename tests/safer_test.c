/* author: cocomelonc */
#include "safer.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void from_hex(uint8_t output[8], const char *hex) {
  for (size_t i = 0; i < 8; ++i) {
    unsigned int byte;
    assert(sscanf(hex + 2 * i, "%2x", &byte) == 1);
    output[i] = (uint8_t)byte;
  }
}

static void known_answers(void) {
  /* First four cases are SAFER K-64 with six rounds, not SK-64:
   * https://github.com/weidai11/cryptopp/blob/master/TestData/saferval.dat
   * Parameter selection: ValidateSAFER() in validat4.cpp.
   * The fifth case is LibTomCrypt's safer_k64_test(), same six-round profile:
   * https://github.com/libtom/libtomcrypt/blob/develop/src/ciphers/safer/safer.c */
  const struct { const char *key, *plain, *cipher; } cases[] = {
      {"0000000000000000", "0000000000000000", "032808C90EE7AB7F"},
      {"0000000000000000", "0102030405060708", "7D28038633B92EB4"},
      {"0102030405060708", "1011121314151617", "71E5CF7F083A59C5"},
      {"0102030405060708", "18191A1B1C1D1E1F", "356F702CC7FA8161"},
      {"0807060504030201", "0102030405060708", "C8F29CDD87783ED9"}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    uint8_t key[9], plain[8], expected[8], block[10];
    uint8_t schedule[SAFER_SCHEDULE_SIZE + 2], saved[SAFER_SCHEDULE_SIZE];
    key[0] = 0xa5;
    from_hex(key + 1, cases[i].key);
    from_hex(plain, cases[i].plain);
    from_hex(expected, cases[i].cipher);
    block[0] = 0xa5;
    block[9] = 0x5a;
    memcpy(block + 1, plain, 8);
    safer_encrypt_block(block + 1, key + 1);
    assert(memcmp(block + 1, expected, 8) == 0);
    memcpy(block + 1, expected, 8);
    safer_decrypt_block(block + 1, key + 1);
    assert(memcmp(block + 1, plain, 8) == 0);

    schedule[0] = 0xa5;
    schedule[sizeof(schedule) - 1] = 0x5a;
    safer_expand_key(key + 1, schedule + 1);
    memcpy(saved, schedule + 1, sizeof(saved));
    memcpy(block + 1, plain, 8);
    safer_encrypt_prepared(block + 1, schedule + 1);
    assert(memcmp(block + 1, expected, 8) == 0);
    safer_decrypt_prepared(block + 1, schedule + 1);
    assert(memcmp(block + 1, plain, 8) == 0);
    assert(memcmp(saved, schedule + 1, sizeof(saved)) == 0);
    assert(block[0] == 0xa5 && block[9] == 0x5a && key[0] == 0xa5);
    assert(schedule[0] == 0xa5 && schedule[sizeof(schedule) - 1] == 0x5a);
    uint8_t saved_key[8];
    from_hex(saved_key, cases[i].key);
    assert(memcmp(saved_key, key + 1, 8) == 0);

    /* With IV=P, P1=0 and P2=C xor P, two chained blocks both equal C. */
    uint8_t input[16] = {0}, encrypted[24], restored[24];
    size_t written;
    for (size_t j = 0; j < 8; ++j) input[8 + j] = expected[j] ^ plain[j];
    assert(safer_cbc_encrypt(key + 1, plain, input, sizeof(input), encrypted,
                            sizeof(encrypted), &written));
    assert(written == 24 && memcmp(encrypted, expected, 8) == 0 &&
           memcmp(encrypted + 8, expected, 8) == 0);
    assert(safer_cbc_decrypt(key + 1, plain, encrypted, written, restored,
                            sizeof(restored), &written));
    assert(written == sizeof(input) && memcmp(restored, input, written) == 0);
  }
}

static void round_trip(const uint8_t *plain, size_t length) {
  uint8_t key[8], iv[8], saved_iv[8];
  uint8_t encrypted[131088], restored[131088];
  size_t written, decrypted;
  for (size_t i = 0; i < 8; ++i) {
    key[i] = (uint8_t)(length * 17 + i * 29);
    iv[i] = (uint8_t)(length + i * 31);
  }
  memcpy(saved_iv, iv, 8);
  assert(safer_cbc_encrypt(key, iv, plain, length, encrypted, sizeof(encrypted), &written));
  assert(written == length + 8 - length % 8);
  assert(safer_cbc_decrypt(key, iv, encrypted, written, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(safer_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &decrypted));
  assert(decrypted == written && memcmp(restored, encrypted, written) == 0);
  assert(safer_cbc_decrypt(key, iv, restored, written, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(memcmp(iv, saved_iv, 8) == 0);
  iv[0] ^= 1;
  assert(safer_cbc_encrypt(key, iv, plain, length, restored, sizeof(restored), &decrypted));
  assert(memcmp(restored, encrypted, written) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[8] = {0}, iv[8] = {0}, block[8], output[16];
  size_t written = 99;
  assert(!safer_cbc_encrypt(NULL, iv, NULL, 0, output, sizeof(output), &written) && written == 0);
  assert(!safer_cbc_decrypt(NULL, iv, output, 8, output, sizeof(output), &written));
  assert(!safer_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), NULL));
  assert(!safer_cbc_encrypt(key, NULL, NULL, 0, output, sizeof(output), &written));
  assert(!safer_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  memset(output, 0xa5, sizeof(output));
  assert(!safer_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!safer_cbc_encrypt(key, iv, NULL, 0, output, 7, &written));
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
  assert(safer_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), &written) && written == 8);
  assert(!safer_cbc_decrypt(key, iv, output, 0, output, sizeof(output), &written));
  assert(!safer_cbc_decrypt(key, iv, output, 7, output, sizeof(output), &written));
  assert(!safer_cbc_decrypt(key, iv, output, 8, output, 7, &written));
  assert(safer_cbc_decrypt(key, iv, output, 8, output, sizeof(output), &written) && written == 0);
  for (unsigned int padding = 0; padding < 256; ++padding) {
    if (padding == 1) continue;
    memset(block, 0, sizeof(block));
    block[7] = (uint8_t)padding;
    safer_encrypt_block(block, key);
    assert(!safer_cbc_decrypt(key, iv, block, sizeof(block), output, sizeof(output), &written));
    assert(written == 0);
    for (size_t i = 0; i < 8; ++i) assert(output[i] == 0);
  }
}

int main(void) {
  uint8_t plain[131073];
  const size_t boundaries[] = {65535, 65536, 65537, 131073};
  known_answers();
  invalid_inputs();
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i ^ (i >> 8));
  for (size_t length = 0; length <= 257; ++length) round_trip(plain, length);
  for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i)
    round_trip(plain, boundaries[i]);
  puts("SAFER K-64: five independent vectors, CBC, padding, guards, and large-buffer round trips passed.");
  return 0;
}
