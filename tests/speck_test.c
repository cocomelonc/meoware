/* author: cocomelonc */
#include "speck.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void known_answer(void) {
  /* Implementation Guide 1.1, section 16, byte-oriented Speck128/128 vector:
   * https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf */
  const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  const uint8_t plain[16] = {0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
                             0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c};
  const uint8_t expected[16] = {0x18, 0x0d, 0x57, 0x5c, 0xdf, 0xfe, 0x60, 0x78,
                                0x65, 0x32, 0x78, 0x79, 0x51, 0x98, 0x5d, 0xa6};
  /* Deliberately unaligned inputs; guard bytes also catch block over-writes. */
  uint8_t block[18] = {0xa5}, unaligned_key[17];
  block[17] = 0x5a;
  memcpy(block + 1, plain, 16);
  memcpy(unaligned_key + 1, key, 16);
  speck_encrypt_block(block + 1, unaligned_key + 1);
  assert(memcmp(block + 1, expected, 16) == 0);
  speck_decrypt_block(block + 1, unaligned_key + 1);
  assert(memcmp(block + 1, plain, 16) == 0);
  assert(block[0] == 0xa5 && block[17] == 0x5a);
  assert(memcmp(unaligned_key + 1, key, 16) == 0);

  /* IV=P, P1=0 and P2=C xor P make the first two CBC blocks equal C. */
  uint8_t input[32] = {0}, cipher[48], restored[48];
  size_t written;
  for (size_t i = 0; i < 16; ++i) input[16 + i] = expected[i] ^ plain[i];
  assert(speck_cbc_encrypt(key, plain, input, sizeof(input), cipher, sizeof(cipher), &written));
  assert(written == sizeof(cipher));
  assert(memcmp(cipher, expected, 16) == 0 && memcmp(cipher + 16, expected, 16) == 0);
  assert(speck_cbc_decrypt(key, plain, cipher, written, restored, sizeof(restored), &written));
  assert(written == sizeof(input) && memcmp(restored, input, written) == 0);
}

static void round_trip(const uint8_t *plain, size_t length) {
  uint8_t key[16], iv[16], saved_iv[16];
  uint8_t cipher[32784], restored[32784];
  size_t encrypted, decrypted, in_place;
  for (size_t i = 0; i < 16; ++i) {
    key[i] = (uint8_t)(length * 17 + i * 29);
    iv[i] = (uint8_t)(length + i * 31);
  }
  memcpy(saved_iv, iv, sizeof(iv));
  assert(speck_cbc_encrypt(key, iv, plain, length, cipher, sizeof(cipher), &encrypted));
  assert(encrypted == length + 16 - length % 16);
  assert(speck_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(speck_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &in_place));
  assert(in_place == encrypted && memcmp(cipher, restored, encrypted) == 0);
  assert(speck_cbc_decrypt(key, iv, restored, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(memcmp(iv, saved_iv, sizeof(iv)) == 0);
  iv[0] ^= 1;
  assert(speck_cbc_encrypt(key, iv, plain, length, restored, sizeof(restored), &in_place));
  assert(memcmp(cipher, restored, encrypted) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[16] = {0}, iv[16] = {0}, block[16], output[32];
  size_t written = 99;
  assert(!speck_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(written == 0);
  memset(output, 0xa5, sizeof(output));
  assert(!speck_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!speck_cbc_encrypt(key, iv, NULL, 0, output, 15, &written));
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
  assert(speck_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), &written));
  assert(written == 16);
  assert(!speck_cbc_decrypt(key, iv, output, 0, output, sizeof(output), &written));
  assert(!speck_cbc_decrypt(key, iv, output, 15, output, sizeof(output), &written));
  assert(!speck_cbc_decrypt(key, iv, output, 16, output, 15, &written));
  assert(speck_cbc_decrypt(key, iv, output, 16, output, sizeof(output), &written));
  assert(written == 0);
  for (unsigned int padding = 0; padding < 256; ++padding) {
    if (padding == 1) continue;
    memset(block, 0, sizeof(block));
    block[15] = (uint8_t)padding;
    speck_encrypt_block(block, key);
    assert(!speck_cbc_decrypt(key, iv, block, sizeof(block), output, sizeof(output), &written));
    assert(written == 0);
    for (size_t i = 0; i < sizeof(block); ++i) assert(output[i] == 0);
  }
}

int main(void) {
  uint8_t plain[32768];
  known_answer();
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
  puts("Speck128/128 vector, CBC, padding, boundaries, and five sample round trips passed.");
  return 0;
}
