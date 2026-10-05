/* author: cocomelonc */
#include "xtea.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void known_answers(void) {
  /* 32-cycle, big-endian known answers: Mbed TLS test 1 and Crypto++ test 32.
   * https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-2.28.9/library/xtea.c
   * https://github.com/weidai11/cryptopp/blob/master/TestVectors/tea.txt */
  const uint8_t keys[2][16] = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
                               {0x27, 0xf9, 0x17, 0xb1, 0xc1, 0xda, 0x89, 0x93, 0x60, 0xe2, 0xac,
                                0xaa, 0xa6, 0xeb, 0x92, 0x3d}};
  const uint8_t plain[2][8] = {{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
                               {0xaf, 0x20, 0xa3, 0x90, 0x54, 0x75, 0x71, 0xaa}};
  const uint8_t expected[2][8] = {{0x49, 0x7d, 0xf3, 0xd0, 0x72, 0x61, 0x2c, 0xb5},
                                  {0xd2, 0x64, 0x28, 0xaf, 0x0a, 0x20, 0x22, 0x83}};
  uint8_t block[8], input[16] = {0}, cipher[24], iv[8] = {0};
  size_t written;
  unsigned int i;
  for (i = 0; i < 2; ++i) {
    memcpy(block, plain[i], sizeof(block));
    xtea_encrypt_block(block, keys[i]);
    assert(memcmp(block, expected[i], sizeof(block)) == 0);
    memcpy(block, expected[i], sizeof(block));
    xtea_decrypt_block(block, keys[i]);
    assert(memcmp(block, plain[i], sizeof(block)) == 0);
  }
  /* P1=P, P2=E(P)^P, IV=0 implies C1=C2=E(P). */
  memcpy(input, plain[0], 8);
  for (i = 0; i < 8; ++i) input[8 + i] = expected[0][i] ^ plain[0][i];
  assert(xtea_cbc_encrypt(keys[0], iv, input, sizeof(input), cipher, sizeof(cipher), &written));
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
    assert(xtea_cbc_encrypt(key, iv, original, length, cipher, sizeof(cipher), &encrypted));
    assert(encrypted == length + 8 - length % 8);
    assert(xtea_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
    assert(decrypted == length && memcmp(original, restored, length) == 0);
    memcpy(restored, original, length);
    assert(xtea_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &other_size));
    assert(other_size == encrypted && memcmp(restored, cipher, encrypted) == 0);
    assert(xtea_cbc_decrypt(key, iv, restored, encrypted, restored, sizeof(restored), &decrypted));
    assert(decrypted == length && memcmp(original, restored, length) == 0);
  }
  iv[0] ^= 1;
  assert(xtea_cbc_encrypt(key, iv, original, sizeof(original), other, sizeof(other), &other_size));
  assert(memcmp(other, cipher, encrypted) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[16] = {0}, iv[8] = {0}, cipher[16], output[16];
  uint8_t bad_padding[8];
  size_t written, index;
  unsigned int padding;
  assert(!xtea_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(!xtea_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!xtea_cbc_encrypt(key, iv, NULL, 0, output, 7, &written));
  assert(xtea_cbc_encrypt(key, iv, NULL, 0, cipher, sizeof(cipher), &written));
  assert(!xtea_cbc_decrypt(key, iv, cipher, 0, output, sizeof(output), &written));
  assert(!xtea_cbc_decrypt(key, iv, cipher, 7, output, sizeof(output), &written));
  assert(!xtea_cbc_decrypt(key, iv, cipher, 8, output, 7, &written));
  assert(written == 0);
  for (padding = 0; padding <= 255; ++padding) {
    memset(bad_padding, 0, sizeof(bad_padding));
    bad_padding[7] = (uint8_t)padding;
    xtea_encrypt_block(bad_padding, key);
    if (padding == 1) continue; /* The sole valid suffix in this construction. */
    assert(!xtea_cbc_decrypt(key, iv, bad_padding, 8, output, sizeof(output), &written));
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
    assert(xtea_cbc_encrypt(key, iv, plain, length, cipher, sizeof(cipher), &encrypted));
    assert(xtea_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
    assert(decrypted == length && memcmp(plain, restored, length) == 0);
  }
}

int main(void) {
  known_answers();
  round_trips();
  invalid_inputs();
  bundled_samples();
  puts("XTEA vectors, CBC, padding, boundaries, and five sample round trips passed.");
  return 0;
}
