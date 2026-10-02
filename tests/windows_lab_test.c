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

static void check_algorithm(CryptoAlgorithm algorithm, bool expire) {
  LabSession lab;
  const CryptoInfo *info = crypto_algorithm_info(algorithm);
  char error[256], path[MAX_PATH], directory[MAX_PATH];
  unsigned char header[24];
  unsigned int sample;
  FILE *file;
  assert(lab_initialize(&lab, error, sizeof(error)));
  check_samples(&lab);
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
    fclose(file);
    assert(memcmp(header, "MWA2", 4) == 0);
    assert(header[4] == algorithm && header[5] == info->block_size);
  }
  if (expire) {
    assert(lab_expire_samples(&lab, error, sizeof(error)));
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
  } else {
    sample_path(path, &lab, 1, true);
    change_header(path, 4, 99);
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
    /* TEA and XTEA share block/key sizes but must never share a format ID. */
    change_header(path, 4, (unsigned char)(algorithm == CRYPTO_TEA128_CBC
      ? CRYPTO_XTEA128_CBC : CRYPTO_TEA128_CBC));
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
    change_header(path, 4, (unsigned char)algorithm);
    change_header(path, 5, 0);
    assert(!lab_restore_samples(&lab, error, sizeof(error)));
    change_header(path, 5, (unsigned char)info->block_size);
    assert(lab_restore_samples(&lab, error, sizeof(error)));
    check_samples(&lab);
    assert(!lab_encrypt_samples(&lab, algorithm, error, sizeof(error)));
  }
  for (sample = 1; sample <= LAB_SAMPLE_COUNT; ++sample) {
    sample_path(path, &lab, sample, true);
    assert(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES);
    if (!expire) {
      sample_path(path, &lab, sample, false);
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

static void check_xtea_dispatch(void) {
  /* Crypto++ XTEA test 32; verifies dispatch as well as the block function. */
  const unsigned char key[16] = {
    0x27,0xf9,0x17,0xb1,0xc1,0xda,0x89,0x93,0x60,0xe2,0xac,0xaa,0xa6,0xeb,0x92,0x3d
  };
  const unsigned char plain[8] = { 0xaf,0x20,0xa3,0x90,0x54,0x75,0x71,0xaa };
  const unsigned char expected[8] = { 0xd2,0x64,0x28,0xaf,0x0a,0x20,0x22,0x83 };
  unsigned char iv[16] = { 0 }, encrypted[16], restored[16];
  CryptoContext context;
  ULONG encrypted_size, restored_size;
  assert(crypto_init(&context, CRYPTO_XTEA128_CBC));
  memcpy(context.portable_key, key, sizeof(key));
  assert(crypto_encrypt(&context, iv, plain, sizeof(plain), encrypted, sizeof(encrypted), &encrypted_size));
  assert(encrypted_size == sizeof(encrypted) && memcmp(encrypted, expected, sizeof(expected)) == 0);
  assert(crypto_decrypt(&context, iv, encrypted, encrypted_size, restored, sizeof(restored), &restored_size));
  assert(restored_size == sizeof(plain) && memcmp(restored, plain, sizeof(plain)) == 0);
  crypto_close(&context);
}

int main(void) {
  size_t index;
  check_xtea_dispatch();
  assert(crypto_algorithm_info((CryptoAlgorithm)99) == NULL);
  assert(crypto_algorithm_at(crypto_algorithm_count()) == NULL);
  for (index = 0; index < crypto_algorithm_count(); ++index) {
    const CryptoInfo *info = crypto_algorithm_at(index);
    check_algorithm(info->id, false);
    check_algorithm(info->id, true);
    printf("%s: sample restoration, metadata checks, and expiry passed.\n", info->name);
  }
  return 0;
}
