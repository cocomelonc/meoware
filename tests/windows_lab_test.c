/* author: cocomelonc */
#include "lab.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void sample_path(char path[MAX_PATH], const LabSession *lab, unsigned int sample, bool encrypted) {
  int length = snprintf(path, MAX_PATH, "%s\\Sample%u.txt%s",
    lab_directory(lab), sample, encrypted ? ".meoware" : "");
  assert(length > 0 && length < MAX_PATH);
}

static void check_samples(const LabSession *lab) {
  unsigned int sample;
  for (sample = 1; sample <= LAB_SAMPLE_COUNT; ++sample) {
    char path[MAX_PATH];
    unsigned char actual[32768];
    HRSRC resource = FindResourceA(NULL, MAKEINTRESOURCEA(100 + sample), RT_RCDATA);
    HGLOBAL loaded = LoadResource(NULL, resource);
    const void *expected = LockResource(loaded);
    DWORD size = SizeofResource(NULL, resource);
    FILE *file;
    size_t count;
    assert(resource != NULL && expected != NULL && size < sizeof(actual));
    sample_path(path, lab, sample, false);
    file = fopen(path, "rb");
    assert(file != NULL);
    count = fread(actual, 1, sizeof(actual), file);
    assert(!ferror(file) && feof(file));
    fclose(file);
    assert(count == size && memcmp(actual, expected, size) == 0);
  }
}

static void change_header(const char *path, long offset, unsigned char value) {
  FILE *file = fopen(path, "r+b");
  assert(file != NULL);
  assert(fseek(file, offset, SEEK_SET) == 0);
  assert(fputc(value, file) != EOF);
  assert(fclose(file) == 0);
}

static void check_algorithm(CryptoAlgorithm algorithm, bool expire, bool empty) {
  LabSession lab;
  const CryptoInfo *info = crypto_algorithm_info(algorithm);
  char error[256], path[MAX_PATH], directory[MAX_PATH];
  unsigned char header[24];
  unsigned char first_frame_high = 0;
  uint32_t frames[LAB_SAMPLE_COUNT] = { 0 };
  unsigned int sample;
  FILE *file;
  assert(lab_initialize(&lab, error, sizeof(error)));
  check_samples(&lab);
  if (empty) {
    for (sample = 1; sample <= LAB_SAMPLE_COUNT; ++sample) {
      sample_path(path, &lab, sample, false);
      file = fopen(path, "wb");
      assert(file && fclose(file) == 0);
    }
  }
  assert(!lab_encrypt_samples(&lab, (CryptoAlgorithm)99, error, sizeof(error)));
  assert(lab_encrypt_samples(&lab, algorithm, error, sizeof(error)));
  assert(lab.crypto.selected == algorithm);
  assert(!lab_encrypt_samples(&lab, algorithm, error, sizeof(error)));
  for (sample = 1; sample <= LAB_SAMPLE_COUNT; ++sample) {
    sample_path(path, &lab, sample, false);
    assert(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES);
    sample_path(path, &lab, sample, true);
    file = fopen(path, "rb");
    assert(file != NULL && fread(header, 1, sizeof(header), file) == sizeof(header));
    if (algorithm == CRYPTO_A51) {
      HRSRC resource = FindResourceA(NULL, MAKEINTRESOURCEA(100 + sample), RT_RCDATA);
      DWORD size = empty ? 0 : SizeofResource(NULL, resource);
      assert(fseek(file, 0, SEEK_END) == 0 && ftell(file) == (long)(24 + size));
      assert((header[10] & 0xc0) == 0);
      frames[sample - 1] = header[8] | ((uint32_t)header[9] << 8) | ((uint32_t)header[10] << 16);
      for (unsigned int j = 0; j + 1 < sample; ++j) assert(frames[j] != frames[sample - 1]);
      if (sample == 1) first_frame_high = header[10];
    }
    fclose(file);
    assert(memcmp(header, "MWA2", 4) == 0);
    assert(header[4] == algorithm && header[5] == info->iv_size);
  }
  if (expire) {
    assert(lab_expire_samples(&lab, error, sizeof(error)));
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
  } else {
    sample_path(path, &lab, 1, true);
    change_header(path, 4, 99);
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
    /* Equal key/block sizes do not make different cipher IDs interchangeable. */
    for (size_t index = 0; index < crypto_algorithm_count(); ++index) {
      CryptoAlgorithm other = crypto_algorithm_at(index)->id;
      if (other == algorithm) continue;
      change_header(path, 4, (unsigned char)other);
      assert(!lab_restore_samples(&lab, error, sizeof(error)));
    }
    change_header(path, 4, (unsigned char)algorithm);
    change_header(path, 5, 0);
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
    change_header(path, 5, (unsigned char)info->iv_size);
    if (algorithm == CRYPTO_A51) {
      change_header(path, 10, first_frame_high | 0x80);
      assert(!lab_restore_samples(&lab, error, sizeof(error)));
      change_header(path, 10, first_frame_high);
    }
    assert(lab_restore_samples(&lab, error, sizeof(error)));
    if (!empty) check_samples(&lab);
    assert(!lab_encrypt_samples(&lab, algorithm, error, sizeof(error)));
  }
  for (sample = 1; sample <= LAB_SAMPLE_COUNT; ++sample) {
    sample_path(path, &lab, sample, true);
    assert(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES);
    if (!expire) {
      sample_path(path, &lab, sample, false);
      if (empty) {
        file = fopen(path, "rb");
        assert(file && fgetc(file) == EOF && !ferror(file));
        fclose(file);
      }
      assert(DeleteFileA(path));
    }
  }
  snprintf(directory, sizeof(directory), "%s", lab_directory(&lab));
  lab_close(&lab);
  for (sample = 0; sample < sizeof(lab.crypto); ++sample) {
    assert(((const unsigned char *)&lab.crypto)[sample] == 0);
  }
  assert(RemoveDirectoryA(directory));
  *strrchr(directory, '\\') = '\0';
  assert(RemoveDirectoryA(directory));
}

static void check_portable_dispatch(void) {
  /* Crypto++, NIST and RFC 3713 known answers verify cipher dispatch. */
  const struct {
    CryptoAlgorithm algorithm;
    unsigned char key[16], plain[16], expected[16];
  } cases[] = {
    { CRYPTO_XTEA128_CBC,
      { 0x27,0xf9,0x17,0xb1,0xc1,0xda,0x89,0x93,0x60,0xe2,0xac,0xaa,0xa6,0xeb,0x92,0x3d },
      { 0xaf,0x20,0xa3,0x90,0x54,0x75,0x71,0xaa },
      { 0xd2,0x64,0x28,0xaf,0x0a,0x20,0x22,0x83 } },
    { CRYPTO_RC5128_CBC,
      { 0x91,0x5f,0x46,0x19,0xbe,0x41,0xb2,0x51,0x63,0x55,0xa5,0x01,0x10,0xa9,0xce,0x91 },
      { 0x21,0xa5,0xdb,0xee,0x15,0x4b,0x8f,0x6d },
      { 0xf7,0xc0,0x13,0xac,0x5b,0x2b,0x89,0x52 } },
    { CRYPTO_RC6128_CBC,
      { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78 },
      { 0x02,0x13,0x24,0x35,0x46,0x57,0x68,0x79,0x8a,0x9b,0xac,0xbd,0xce,0xdf,0xe0,0xf1 },
      { 0x52,0x4e,0x19,0x2f,0x47,0x15,0xc6,0x23,0x1f,0x51,0xf6,0x36,0x7e,0xa4,0x3f,0x18 } },
    { CRYPTO_SKIPJACK80_CBC,
      { 0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11 },
      { 0x33,0x22,0x11,0x00,0xdd,0xcc,0xbb,0xaa },
      { 0x25,0x87,0xca,0xe2,0x7a,0x12,0xd3,0x00 } },
    { CRYPTO_CAMELLIA128_CBC,
      { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 },
      { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 },
      { 0x67,0x67,0x31,0x38,0x54,0x96,0x69,0x73,0x08,0x57,0x06,0x56,0x48,0xea,0xbe,0x43 } }
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    unsigned char iv[16] = { 0 }, encrypted[32], restored[32];
    ULONG block_size = crypto_algorithm_info(cases[i].algorithm)->block_size;
    CryptoContext context;
    ULONG encrypted_size, restored_size;
    assert(crypto_init(&context, cases[i].algorithm));
    memcpy(context.portable_key, cases[i].key, sizeof(cases[i].key));
    assert(crypto_encrypt(&context, iv, cases[i].plain, block_size, encrypted, sizeof(encrypted), &encrypted_size));
    assert(encrypted_size == 2 * block_size && memcmp(encrypted, cases[i].expected, block_size) == 0);
    assert(crypto_decrypt(&context, iv, encrypted, encrypted_size, restored, sizeof(restored), &restored_size));
    assert(restored_size == block_size && memcmp(restored, cases[i].plain, block_size) == 0);
    crypto_close(&context);
  }
}

static void check_stream_dispatch(void) {
  const unsigned char key[8] = { 0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01 };
  const unsigned char expected[14] = { 0xcb,0xa2,0x55,0x76,0x17,0x5d,0x3b,0x1c,0x7b,0x2f,0x29,0xa8,0xc1,0xb6 };
  unsigned char iv[16] = { 0 }, plain[14] = { 0 }, cipher[14], restored[14];
  uint32_t frame = ((123456U / 1326) << 11) | ((123456U % 51) << 5) | (123456U % 26);
  CryptoContext context;
  ULONG size;
  assert(crypto_init(&context, CRYPTO_A51));
  memcpy(context.portable_key, key, sizeof(key));
  for (unsigned int i = 0; i < A51_IV_SIZE; ++i) iv[i] = (unsigned char)(frame >> (8 * i));
  assert(crypto_encrypt(&context, iv, plain, sizeof(plain), cipher, sizeof(cipher), &size));
  assert(size == sizeof(plain) && !memcmp(cipher, expected, size));
  assert(crypto_decrypt(&context, iv, cipher, size, restored, sizeof(restored), &size));
  assert(size == sizeof(plain) && !memcmp(restored, plain, size));
  assert(crypto_encrypt(&context, iv, NULL, 0, cipher, 0, &size) && size == 0);
  assert(crypto_decrypt(&context, iv, cipher, 0, restored, 0, &size) && size == 0);
  iv[2] |= 0x80;
  assert(!crypto_decrypt(&context, iv, cipher, 1, restored, sizeof(restored), &size) && size == 0);
  crypto_close(&context);
  for (size_t i = 0; i < sizeof(context.portable_key); ++i) assert(context.portable_key[i] == 0);
}

int main(void) {
  size_t index;
  check_portable_dispatch();
  check_stream_dispatch();
  assert(crypto_algorithm_info((CryptoAlgorithm)99) == NULL);
  assert(crypto_algorithm_at(crypto_algorithm_count()) == NULL);
  for (index = 0; index < crypto_algorithm_count(); ++index) {
    const CryptoInfo *info = crypto_algorithm_at(index);
    check_algorithm(info->id, false, false);
    check_algorithm(info->id, true, false);
    printf("%s: sample restoration, metadata checks, and expiry passed.\n", info->name);
  }
  check_algorithm(CRYPTO_A51, false, true);
  return 0;
}
