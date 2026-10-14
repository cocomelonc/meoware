/* author: cocomelonc */
#include "mars.h"
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

static void test_known_answer(void) {
  const char *vectors[][3] = {
      {"00000000000000000000000000000000", "00000000000000000000000000000000",
       "DCC07B8DFB0738D6E30A22DFCF27E886"},
      {"00000000000000000000000000000000", "DCC07B8DFB0738D6E30A22DFCF27E886",
       "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF"}};
  uint8_t key[MARS_KEY_SIZE], block[MARS_BLOCK_SIZE], plain[MARS_BLOCK_SIZE],
      expected[MARS_BLOCK_SIZE];
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
    decode_hex(vectors[i][0], key);
    decode_hex(vectors[i][1], plain);
    decode_hex(vectors[i][2], expected);
    memcpy(block, plain, sizeof(block));
    mars_encrypt_block(block, key);
    assert(memcmp(block, expected, sizeof(block)) == 0);
    mars_decrypt_block(block, key);
    assert(memcmp(block, plain, sizeof(block)) == 0);
  }
}

static void test_cbc_round_trip(void) {
  uint8_t key[MARS_KEY_SIZE] = {0, 1, 2, 3}, iv[MARS_BLOCK_SIZE] = {4, 5, 6};
  uint8_t plain[49], encrypted[64], restored[64];
  size_t encrypted_size = 0, restored_size = 0;
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i * 13U);
  assert(cbc_encrypt(mars_encrypt_block, MARS_BLOCK_SIZE, key, iv, plain, sizeof(plain), encrypted,
                     sizeof(encrypted), &encrypted_size));
  assert(encrypted_size == 64);
  assert(cbc_decrypt(mars_decrypt_block, MARS_BLOCK_SIZE, key, iv, encrypted, encrypted_size,
                     restored, sizeof(restored), &restored_size));
  assert(restored_size == sizeof(plain) && memcmp(plain, restored, sizeof(plain)) == 0);
  encrypted[encrypted_size - 1] ^= 1;
  assert(!cbc_decrypt(mars_decrypt_block, MARS_BLOCK_SIZE, key, iv, encrypted, encrypted_size,
                      restored, sizeof(restored), &restored_size));
}

int main(void) {
  test_known_answer();
  test_cbc_round_trip();
  puts("MARS-128 vector and CBC round trips passed.");
  return 0;
}
