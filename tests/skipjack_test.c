/* author: cocomelonc */
#include "skipjack.h"
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
  /* NIST SKIPJACK specification, Annex III.A (codebook test vector). */
  uint8_t key[SKIPJACK_KEY_SIZE], plain[8], expected[8], block[8];
  decode_hex("00998877665544332211", key);
  decode_hex("33221100ddccbbaa", plain);
  decode_hex("2587cae27a12d300", expected);
  memcpy(block, plain, sizeof(block));
  skipjack_encrypt_block(block, key);
  assert(memcmp(block, expected, sizeof(block)) == 0);
  skipjack_decrypt_block(block, key);
  assert(memcmp(block, plain, sizeof(block)) == 0);

  /* P2 = P1 XOR C1 gives C2 = C1 with IV=0. */
  uint8_t iv[8] = { 0 }, input[16], cipher[24];
  size_t written;
  memcpy(input, plain, 8);
  for (unsigned int i = 0; i < 8; ++i) input[8 + i] = plain[i] ^ expected[i];
  assert(skipjack_cbc_encrypt(key, iv, input, sizeof(input), cipher, sizeof(cipher), &written));
  assert(written == sizeof(cipher));
  assert(memcmp(cipher, expected, 8) == 0 && memcmp(cipher + 8, expected, 8) == 0);

  /* Exercise all 80 key bits, including the final two key bytes. */
  for (unsigned int bit = 0; bit < 80; ++bit) {
    key[bit / 8] ^= (uint8_t)(1U << (bit % 8));
    memcpy(block, plain, sizeof(block));
    skipjack_encrypt_block(block, key);
    assert(memcmp(block, expected, sizeof(block)) != 0);
    skipjack_decrypt_block(block, key);
    assert(memcmp(block, plain, sizeof(block)) == 0);
    key[bit / 8] ^= (uint8_t)(1U << (bit % 8));
  }
}

static void round_trip(const uint8_t *plain, size_t length) {
  uint8_t key[SKIPJACK_KEY_SIZE] = { 1, 2, 3 }, iv[8] = { 4, 5, 6 };
  uint8_t cipher[32776], restored[32776];
  size_t encrypted, decrypted, in_place;
  assert(skipjack_cbc_encrypt(key, iv, plain, length, cipher, sizeof(cipher), &encrypted));
  assert(encrypted == length + 8 - length % 8);
  assert(skipjack_cbc_decrypt(key, iv, cipher, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  assert(skipjack_cbc_encrypt(key, iv, restored, length, restored, sizeof(restored), &in_place));
  assert(in_place == encrypted && memcmp(cipher, restored, encrypted) == 0);
  assert(skipjack_cbc_decrypt(key, iv, restored, encrypted, restored, sizeof(restored), &decrypted));
  assert(decrypted == length && memcmp(plain, restored, length) == 0);
  iv[0] ^= 1;
  assert(skipjack_cbc_encrypt(key, iv, plain, length, restored, sizeof(restored), &in_place));
  assert(memcmp(cipher, restored, encrypted) != 0);
}

static void invalid_inputs(void) {
  uint8_t key[SKIPJACK_KEY_SIZE] = { 0 }, iv[8] = { 0 }, block[8], output[16];
  size_t written;
  assert(!skipjack_cbc_encrypt(key, iv, NULL, 1, output, sizeof(output), &written));
  assert(!skipjack_cbc_encrypt(key, iv, output, SIZE_MAX, output, SIZE_MAX, &written));
  assert(!skipjack_cbc_encrypt(key, iv, NULL, 0, output, 7, &written));
  assert(skipjack_cbc_encrypt(key, iv, NULL, 0, output, sizeof(output), &written));
  assert(!skipjack_cbc_decrypt(key, iv, output, 0, output, sizeof(output), &written));
  assert(!skipjack_cbc_decrypt(key, iv, output, 7, output, sizeof(output), &written));
  assert(!skipjack_cbc_decrypt(key, iv, output, 8, output, 7, &written));
  for (unsigned int padding = 0; padding < 256; ++padding) {
    memset(block, 0, sizeof(block));
    block[7] = (uint8_t)padding;
    skipjack_encrypt_block(block, key);
    if (padding == 1) continue;
    assert(!skipjack_cbc_decrypt(key, iv, block, sizeof(block), output, sizeof(output), &written));
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
  puts("Skipjack vectors, CBC, padding, boundaries, and five sample round trips passed.");
  return 0;
}
