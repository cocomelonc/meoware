/* author: cocomelonc */
#include "a51.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void check_vector(void) {
  /* Osmocom's A5/1 test: both 114-bit directions, with its key-byte order
   * reversed for this API and GSM FN=123456 converted to raw COUNT.
   * https://github.com/osmocom/libosmocore/blob/master/tests/a5/a5_test.c */
  const uint8_t key[8] = { 0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01 };
  const uint8_t expected[2][15] = {
    { 0xcb,0xa2,0x55,0x76,0x17,0x5d,0x3b,0x1c,0x7b,0x2f,0x29,0xa8,0xc1,0xb6,0x00 },
    { 0xd9,0x03,0x5e,0x0f,0x2a,0xec,0x13,0x9a,0x05,0xd4,0xa8,0x7b,0xb1,0x64,0x80 }
  };
  uint32_t frame = ((123456U / 1326) << 11) | ((123456U % 51) << 5) | (123456U % 26);
  uint8_t plain[29] = { 0 }, output[29], restored[29];
  size_t written;
  assert(a51_crypt(key, frame, plain, sizeof(plain), output, sizeof(output), &written));
  assert(written == sizeof(plain));
  for (unsigned int direction = 0; direction < 2; ++direction) {
    for (unsigned int bit = 0; bit < 114; ++bit) {
      unsigned int position = direction * 114 + bit;
      assert(((output[position / 8] >> (7 - position % 8)) & 1) ==
             ((expected[direction][bit / 8] >> (7 - bit % 8)) & 1));
    }
  }
  assert(a51_crypt(key, frame, output, sizeof(output), restored, sizeof(restored), &written));
  assert(!memcmp(plain, restored, sizeof(plain)));
}

int main(void) {
  const uint8_t key[8] = { 1,2,3,4,5,6,7,8 };
  uint8_t plain[32768], cipher[32768], restored[32768];
  size_t written = 0;
  check_vector();
  for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i * 37);
  for (size_t length = 0; length <= 257; ++length) {
    assert(a51_crypt(key, A51_FRAME_MASK, plain, length, cipher, length, &written));
    assert(written == length);
    assert(a51_crypt(key, A51_FRAME_MASK, cipher, length, restored, length, &written));
    assert(written == length && !memcmp(plain, restored, length));
    memcpy(restored, plain, length);
    assert(a51_crypt(key, A51_FRAME_MASK, restored, length, restored, length, &written));
    assert(!memcmp(restored, cipher, length));
    assert(a51_crypt(key, A51_FRAME_MASK, restored, length, restored, length, &written));
    assert(!memcmp(restored, plain, length));
  }
  assert(a51_crypt(key, 1, plain, 32, cipher, 32, &written));
  assert(a51_crypt(key, 2, plain, 32, restored, 32, &written));
  assert(memcmp(cipher, restored, 32));
  uint8_t changed_key[8];
  memcpy(changed_key, key, sizeof(key)); changed_key[0] ^= 1;
  assert(a51_crypt(changed_key, 1, plain, 32, restored, 32, &written));
  assert(memcmp(cipher, restored, 32));

  memset(cipher, 0xa5, sizeof(cipher));
  assert(!a51_crypt(key, A51_FRAME_MASK + 1, plain, 1, cipher, sizeof(cipher), &written));
  assert(written == 0 && cipher[0] == 0xa5);
  assert(!a51_crypt(NULL, 0, plain, 1, cipher, sizeof(cipher), &written));
  assert(!a51_crypt(key, 0, NULL, 1, cipher, sizeof(cipher), &written));
  assert(!a51_crypt(key, 0, plain, 1, NULL, sizeof(cipher), &written));
  assert(!a51_crypt(key, 0, plain, 1, cipher, 0, &written));
  assert(!a51_crypt(key, 0, plain, SIZE_MAX, cipher, sizeof(cipher), &written));
  assert(!a51_crypt(key, 0, plain, 1, cipher, sizeof(cipher), NULL));
  assert(a51_crypt(key, 0, NULL, 0, cipher, 0, &written) && written == 0);
  assert(cipher[0] == 0xa5);

  for (unsigned int sample = 1; sample <= 5; ++sample) {
    char path[64];
    snprintf(path, sizeof(path), "assets/sample%u.txt", sample);
    FILE *file = fopen(path, "rb");
    assert(file);
    size_t length = fread(plain, 1, sizeof(plain), file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    assert(a51_crypt(key, sample, plain, length, cipher, sizeof(cipher), &written));
    assert(written == length);
    assert(a51_crypt(key, sample, cipher, length, restored, sizeof(restored), &written));
    assert(written == length && !memcmp(plain, restored, length));
  }
  puts("A5/1 published vector, stream boundaries, in-place, and five sample round trips passed.");
  return 0;
}
