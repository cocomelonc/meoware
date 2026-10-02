/* author: cocomelonc */
#include "rc6.h"
#include "cbc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void decode_hex(const char *text, uint8_t *bytes) {
  for (size_t i = 0; text[2 * i] != '\0'; ++i) {
    unsigned int value;
    assert(sscanf(text + 2 * i, "%2x", &value) == 1);
    bytes[i] = (uint8_t)value;
  }
}

static void known_answers(void) {
  /* RC6-32/20/16 vectors: https://github.com/weidai11/cryptopp/blob/master/TestData/rc6val.dat */
  const char *vectors[][3] = {
    { "00000000000000000000000000000000", "00000000000000000000000000000000", "8fc3a53656b1f778c129df4e9848a41e" },
    { "0123456789abcdef0112233445566778", "02132435465768798a9bacbdcedfe0f1", "524e192f4715c6231f51f6367ea43f18" }
  };
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    uint8_t key[16], plain[16], expected[16], block[16];
    decode_hex(vectors[i][0], key);
    decode_hex(vectors[i][1], plain);
    decode_hex(vectors[i][2], expected);
    memcpy(block, plain, sizeof(block));
    rc6_encrypt_block(block, key);
    assert(memcmp(block, expected, sizeof(block)) == 0);
    rc6_decrypt_block(block, key);
    assert(memcmp(block, plain, sizeof(block)) == 0);
  }
  /* With IV=0, P1=0 and P2=E(0), the first two CBC blocks both equal E(0). */
  uint8_t key[16] = { 0 }, iv[16] = { 0 }, input[32] = { 0 }, cipher[48];
  size_t written;
  decode_hex(vectors[0][2], input + 16);
  assert(rc6_cbc_encrypt(key, iv, input, sizeof(input), cipher, sizeof(cipher), &written));
  assert(written == sizeof(cipher));
  assert(memcmp(cipher, input + 16, 16) == 0 && memcmp(cipher + 16, input + 16, 16) == 0);
}

static void round_trip(const uint8_t *plain, size_t length) {
  uint8_t key[16] = { 1, 2, 3 }, iv[16] = { 4, 5, 6 };
  uint8_t cipher[32784], restored[32784];
  size_t encrypted, decrypted, in_place;
  assert(rc6_cbc_encrypt(key, iv, plain, length, cipher, sizeof(cipher), &encrypted));
  assert(encrypted == length + 16 - length % 16);
  assert(rc6_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(rc6_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &in_place));
  assert(in_place == encrypted && memcmp(cipher, restored, encrypted) == 0);
  assert(rc6_cbc_decrypt(key, iv, restored, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  iv[0] ^= 1;
  assert(rc6_cbc_encrypt(key, iv, plain, length, restored, sizeof(restored), &in_place));
  assert(memcmp(cipher, restored, encrypted) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[16] = { 0 }, iv[16] = { 0 }, block[16], output[32];
  size_t written;
  const size_t invalid_sizes[] = { 0, 7, 17, SIZE_MAX };
  for (size_t i = 0; i < sizeof(invalid_sizes) / sizeof(invalid_sizes[0]); ++i) {
    assert(!cbc_encrypt(rc6_encrypt_block, invalid_sizes[i], key, iv, NULL, 0, output, sizeof(output), &written));
    assert(written == 0);
    assert(!cbc_decrypt(rc6_decrypt_block, invalid_sizes[i], key, iv, output, 16, output, sizeof(output), &written));
    assert(written == 0);
  }
  assert(!rc6_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(!rc6_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!rc6_cbc_encrypt(key, iv, NULL, 0, output, 15, &written));
  assert(rc6_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), &written));
  assert(!rc6_cbc_decrypt(key, iv, output, 0, output, sizeof(output), &written));
  assert(!rc6_cbc_decrypt(key, iv, output, 15, output, sizeof(output), &written));
  assert(!rc6_cbc_decrypt(key, iv, output, 16, output, 15, &written));
  for (unsigned int padding = 0; padding < 256; ++padding) {
    memset(block, 0, sizeof(block));
    block[15] = (uint8_t)padding;
    rc6_encrypt_block(block, key);
    if (padding == 1) continue;
    assert(!rc6_cbc_decrypt(key, iv, block, sizeof(block), output, sizeof(output), &written));
    assert(written == 0);
    for (size_t i = 0; i < sizeof(block); ++i) assert(output[i] == 0);
  }
}

int main(void) {
  uint8_t plain[32768];
  known_answers();
  invalid_inputs();
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)i;
  for (size_t length = 0; length <= 513; ++length) round_trip(plain, length);
  for (unsigned int sample = 1; sample <= 5; ++sample) {
    char path[64];
    snprintf(path, sizeof(path), "assets/sample%u.txt", sample);
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    size_t length = fread(plain, 1, sizeof(plain), file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    round_trip(plain, length);
  }
  puts("RC6 vectors, CBC, padding, boundaries, and five sample round trips passed.");
  return 0;
}
