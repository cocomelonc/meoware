/* author: cocomelonc */
#include "rc5.h"
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
  /* RC5-32/12/16 vectors: https://github.com/weidai11/cryptopp/blob/master/TestData/rc5val.dat */
  const char *vectors[][3] = {
      {"00000000000000000000000000000000", "0000000000000000", "21a5dbee154b8f6d"},
      {"915f4619be41b2516355a50110a9ce91", "21a5dbee154b8f6d", "f7c013ac5b2b8952"},
      {"783348e75aeb0f2fd7b169bb8dc16787", "f7c013ac5b2b8952", "2f42b3b70369fc92"},
      {"dc49db1375a5584f6485b413b5f12baf", "2f42b3b70369fc92", "65c178b284d197cc"},
      {"5269f149d41ba0152497574d7f153125", "65c178b284d197cc", "eb44e415da319824"}};
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    uint8_t key[16], plain[8], expected[8], block[8];
    decode_hex(vectors[i][0], key);
    decode_hex(vectors[i][1], plain);
    decode_hex(vectors[i][2], expected);
    memcpy(block, plain, sizeof(block));
    rc5_encrypt_block(block, key);
    assert(memcmp(block, expected, sizeof(block)) == 0);
    rc5_decrypt_block(block, key);
    assert(memcmp(block, plain, sizeof(block)) == 0);
  }
  /* With IV=0, P1=0 and P2=E(0), the first two CBC blocks both equal E(0). */
  uint8_t key[16] = {0}, iv[8] = {0}, input[16] = {0}, cipher[24];
  size_t written;
  decode_hex(vectors[0][2], input + 8);
  assert(rc5_cbc_encrypt(key, iv, input, sizeof(input), cipher, sizeof(cipher), &written));
  assert(written == sizeof(cipher));
  assert(memcmp(cipher, input + 8, 8) == 0 && memcmp(cipher + 8, input + 8, 8) == 0);
}

static void round_trip(const uint8_t *plain, size_t length) {
  uint8_t key[16] = {1, 2, 3}, iv[8] = {4, 5, 6};
  uint8_t cipher[32776], restored[32776];
  size_t encrypted, decrypted, in_place;
  assert(rc5_cbc_encrypt(key, iv, plain, length, cipher, sizeof(cipher), &encrypted));
  assert(encrypted == length + 8 - length % 8);
  assert(rc5_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(rc5_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &in_place));
  assert(in_place == encrypted && memcmp(cipher, restored, encrypted) == 0);
  assert(rc5_cbc_decrypt(key, iv, restored, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  iv[0] ^= 1;
  assert(rc5_cbc_encrypt(key, iv, plain, length, restored, sizeof(restored), &in_place));
  assert(memcmp(cipher, restored, encrypted) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[16] = {0}, iv[8] = {0}, block[8], output[16];
  size_t written;
  assert(!rc5_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(!rc5_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!rc5_cbc_encrypt(key, iv, NULL, 0, output, 7, &written));
  assert(rc5_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), &written));
  assert(!rc5_cbc_decrypt(key, iv, output, 0, output, sizeof(output), &written));
  assert(!rc5_cbc_decrypt(key, iv, output, 7, output, sizeof(output), &written));
  assert(!rc5_cbc_decrypt(key, iv, output, 8, output, 7, &written));
  for (unsigned int padding = 0; padding < 256; ++padding) {
    memset(block, 0, sizeof(block));
    block[7] = (uint8_t)padding;
    rc5_encrypt_block(block, key);
    if (padding == 1) continue;
    assert(!rc5_cbc_decrypt(key, iv, block, sizeof(block), output, sizeof(output), &written));
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
  puts("RC5 vectors, CBC, padding, boundaries, and five sample round trips passed.");
  return 0;
}
