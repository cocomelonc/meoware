/* author: cocomelonc */
#include "tea.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void known_answers(void) {
  /* Published TEA vectors 1 and 5 (big endian):
   * https://github.com/weidai11/cryptopp/blob/master/TestVectors/tea.txt */
  const uint8_t keys[2][16] = {{0},
                               {0x41, 0xea, 0x3a, 0x0a, 0x4e, 0x8e, 0x78, 0x29, 0xc8, 0x8b, 0xa9,
                                0x5e, 0xb8, 0x4e, 0x28, 0xaf}};
  const uint8_t plain[2][8] = {{0}, {0xb6, 0xb6, 0x20, 0x88, 0, 0, 0, 0}};
  const uint8_t expected[2][8] = {{0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40},
                                  {0xa0, 0xa4, 0x72, 0x95, 0x8f, 0xad, 0xf3, 0xb3}};
  uint8_t block[8], input[16] = {0}, cipher[24], iv[8] = {0};
  size_t written;
  unsigned int i;
  for (i = 0; i < 2; ++i) {
    memcpy(block, plain[i], sizeof(block));
    tea_encrypt_block(block, keys[i]);
    assert(memcmp(block, expected[i], sizeof(block)) == 0);
    memcpy(block, expected[i], sizeof(block));
    tea_decrypt_block(block, keys[i]);
    assert(memcmp(block, plain[i], sizeof(block)) == 0);
  }
  /* P1=0, P2=E(0), IV=0 implies C1=C2=E(0). */
  memcpy(input + 8, expected[0], 8);
  assert(tea_cbc_encrypt(keys[0], iv, input, sizeof(input), cipher, sizeof(cipher), &written));
  assert(written == 24);
  assert(memcmp(cipher, expected[0], 8) == 0);
  assert(memcmp(cipher + 8, expected[0], 8) == 0);
}

static void round_trips(void) {
  uint8_t key[16], iv[8], original[513], cipher[528], restored[528], other[528];
  size_t length, index, encrypted, decrypted, other_size;
  for (index = 0; index < sizeof(key); ++index) key[index] = (uint8_t)(index * 17 + 3);
  for (index = 0; index < sizeof(iv); ++index) iv[index] = (uint8_t)(index * 29 + 1);
  for (index = 0; index < sizeof(original); ++index) original[index] = (uint8_t)index;
  for (length = 0; length <= sizeof(original); ++length) {
    assert(tea_cbc_encrypt(key, iv, original, length, cipher, sizeof(cipher), &encrypted));
    assert(encrypted == length + 8 - length % 8);
    assert(tea_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
    assert(decrypted == length && memcmp(original, restored, length) == 0);
    memcpy(restored, original, length);
    assert(tea_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &other_size));
    assert(other_size == encrypted && memcmp(restored, cipher, encrypted) == 0);
    assert(tea_cbc_decrypt(key, iv, restored, encrypted, restored, sizeof(restored), &decrypted));
    assert(decrypted == length && memcmp(original, restored, length) == 0);
  }
  iv[0] ^= 1;
  assert(tea_cbc_encrypt(key, iv, original, sizeof(original), other, sizeof(other), &other_size));
  assert(memcmp(other, cipher, encrypted) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[16] = {0}, iv[8] = {0}, cipher[16], output[16];
  uint8_t bad_padding[8];
  size_t written, index;
  unsigned int padding;
  assert(!tea_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(!tea_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!tea_cbc_encrypt(key, iv, NULL, 0, output, 7, &written));
  assert(tea_cbc_encrypt(key, iv, NULL, 0, cipher, sizeof(cipher), &written));
  assert(!tea_cbc_decrypt(key, iv, cipher, 0, output, sizeof(output), &written));
  assert(!tea_cbc_decrypt(key, iv, cipher, 7, output, sizeof(output), &written));
  assert(!tea_cbc_decrypt(key, iv, cipher, 8, output, 7, &written));
  assert(written == 0);
  for (padding = 0; padding <= 255; ++padding) {
    memset(bad_padding, 0, sizeof(bad_padding));
    bad_padding[7] = (uint8_t)padding;
    tea_encrypt_block(bad_padding, key);
    if (padding == 1) continue; /* The sole valid suffix in this construction. */
    assert(!tea_cbc_decrypt(key, iv, bad_padding, 8, output, sizeof(output), &written));
    assert(written == 0);
    for (index = 0; index < 8; ++index) assert(output[index] == 0);
  }
}

static void bundled_samples(void) {
  uint8_t plain[32768], cipher[32776], restored[32776];
  uint8_t key[16] = {1, 2, 3}, iv[8] = {4, 5, 6};
  unsigned int sample;
  for (sample = 1; sample <= 5; ++sample) {
    char path[64];
    FILE *file;
    size_t length, encrypted, decrypted;
    snprintf(path, sizeof(path), "assets/sample%u.txt", sample);
    file = fopen(path, "rb");
    assert(file != NULL);
    length = fread(plain, 1, sizeof(plain), file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    assert(tea_cbc_encrypt(key, iv, plain, length, cipher, sizeof(cipher), &encrypted));
    assert(tea_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
    assert(decrypted == length && memcmp(plain, restored, length) == 0);
  }
}

int main(void) {
  known_answers();
  round_trips();
  invalid_inputs();
  bundled_samples();
  puts("TEA vectors, CBC, padding, boundaries, and five sample round trips passed.");
  return 0;
}
