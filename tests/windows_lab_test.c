/* author: cocomelonc */
#include "lab.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void fixture_path(char path[MAX_PATH], const LabSession *lab, const char *relative,
                         bool encrypted) {
  int length = snprintf(path, MAX_PATH, "%s\\%s%s", lab_directory(lab), relative,
                        encrypted ? ".meoware" : "");
  assert(length > 0 && length < MAX_PATH);
}

static void create_pattern_file(const char *path, size_t size, unsigned int seed) {
  HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  unsigned char buffer[8192];
  size_t offset = 0;
  assert(file != INVALID_HANDLE_VALUE);
  while (offset < size) {
    size_t take = size - offset < sizeof(buffer) ? size - offset : sizeof(buffer);
    DWORD written = 0;
    for (size_t i = 0; i < take; ++i)
      buffer[i] = (unsigned char)(((offset + i) * 31U + seed * 17U + ((offset + i) >> 8)) & 0xff);
    assert(WriteFile(file, buffer, (DWORD)take, &written, NULL) && written == take);
    offset += take;
  }
  assert(FlushFileBuffers(file));
  assert(CloseHandle(file));
}

static void check_pattern_file(const char *path, size_t size, unsigned int seed) {
  HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
  unsigned char buffer[8192];
  size_t offset = 0;
  assert(file != INVALID_HANDLE_VALUE);
  while (offset < size) {
    size_t take = size - offset < sizeof(buffer) ? size - offset : sizeof(buffer);
    DWORD got = 0;
    assert(ReadFile(file, buffer, (DWORD)take, &got, NULL) && got == take);
    for (size_t i = 0; i < take; ++i)
      assert(buffer[i] == (unsigned char)(((offset + i) * 31U + seed * 17U +
                                          ((offset + i) >> 8)) & 0xff));
    offset += take;
  }
  {
    DWORD got = 0;
    unsigned char extra;
    assert(ReadFile(file, &extra, 1, &got, NULL) && got == 0);
  }
  assert(CloseHandle(file));
}

static void create_fixture_tree(const LabSession *lab) {
  char path[MAX_PATH];
  assert(snprintf(path, sizeof(path), "%s\\docs", lab_directory(lab)) > 0);
  assert(CreateDirectoryA(path, NULL));
  assert(snprintf(path, sizeof(path), "%s\\media", lab_directory(lab)) > 0);
  assert(CreateDirectoryA(path, NULL));
  assert(snprintf(path, sizeof(path), "%s\\docs\\payload.bin", lab_directory(lab)) > 0);
  create_pattern_file(path, 140123, 3);
  assert(snprintf(path, sizeof(path), "%s\\media\\chunked.bin", lab_directory(lab)) > 0);
  create_pattern_file(path, 65537, 9);
  assert(snprintf(path, sizeof(path), "%s\\empty.bin", lab_directory(lab)) > 0);
  create_pattern_file(path, 0, 1);
}

static void cleanup_lab(LabSession *lab) {
  char path[MAX_PATH], parent[MAX_PATH];
  snprintf(path, sizeof(path), "%s\\docs\\payload.bin", lab_directory(lab));
  DeleteFileA(path);
  snprintf(path, sizeof(path), "%s\\media\\chunked.bin", lab_directory(lab));
  DeleteFileA(path);
  snprintf(path, sizeof(path), "%s\\empty.bin", lab_directory(lab));
  DeleteFileA(path);
  snprintf(path, sizeof(path), "%s\\docs", lab_directory(lab));
  RemoveDirectoryA(path);
  snprintf(path, sizeof(path), "%s\\media", lab_directory(lab));
  RemoveDirectoryA(path);
  snprintf(path, sizeof(path), "%s", lab_directory(lab));
  RemoveDirectoryA(path);
  snprintf(parent, sizeof(parent), "%s", lab_directory(lab));
  *strrchr(parent, '\\') = '\0';
  RemoveDirectoryA(parent);
}

static void check_algorithm(CryptoAlgorithm algorithm, bool expire) {
  LabSession lab;
  const CryptoInfo *info = crypto_algorithm_info(algorithm);
  char error[256] = {0}, path[MAX_PATH];
  unsigned char header[32];
  FILE *file;
  assert(lab_initialize(&lab, error, sizeof(error)));
  create_fixture_tree(&lab);
  assert(!lab_encrypt_tree(&lab, (CryptoAlgorithm)99, error, sizeof(error)));
  memset(error, 0, sizeof(error));
  assert(lab_encrypt_tree(&lab, algorithm, error, sizeof(error)));
  assert(lab.crypto.selected == algorithm);
  assert(lab.file_count == 3);
  assert(!lab_encrypt_tree(&lab, algorithm, error, sizeof(error)));
  {
    const char *fixtures[] = {"docs\\payload.bin", "media\\chunked.bin", "empty.bin"};
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) {
      fixture_path(path, &lab, fixtures[i], false);
      assert(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES);
      fixture_path(path, &lab, fixtures[i], true);
      file = fopen(path, "rb");
      assert(file != NULL && fread(header, 1, sizeof(header), file) == sizeof(header));
      fclose(file);
      assert(memcmp(header, "MWA3", 4) == 0);
      assert(header[4] == algorithm && header[5] == info->iv_size);
    }
  }
  if (expire) {
    assert(lab_expire_tree(&lab, error, sizeof(error)));
    assert(!lab_restore_tree(&lab, error, sizeof(error)));
  } else {
    fixture_path(path, &lab, "docs\\payload.bin", true);
    file = fopen(path, "r+b");
    assert(file != NULL && fseek(file, -1, SEEK_END) == 0);
    {
      int original_tag_byte = fgetc(file);
      assert(original_tag_byte != EOF && fseek(file, -1, SEEK_END) == 0);
      assert(fputc(original_tag_byte ^ 0xff, file) != EOF);
      assert(fclose(file) == 0);
      assert(!lab_restore_tree(&lab, error, sizeof(error)));
      file = fopen(path, "r+b");
      assert(file != NULL && fseek(file, -1, SEEK_END) == 0);
      assert(fputc(original_tag_byte, file) != EOF && fclose(file) == 0);
    }
    memset(error, 0, sizeof(error));
    assert(lab_restore_tree(&lab, error, sizeof(error)));
    fixture_path(path, &lab, "docs\\payload.bin", false);
    check_pattern_file(path, 140123, 3);
    fixture_path(path, &lab, "media\\chunked.bin", false);
    check_pattern_file(path, 65537, 9);
    fixture_path(path, &lab, "empty.bin", false);
    check_pattern_file(path, 0, 1);
    assert(!lab_encrypt_tree(&lab, algorithm, error, sizeof(error)));
  }
  lab_close(&lab);
  cleanup_lab(&lab);
}

static void check_portable_dispatch(void) {
  /* Published known answers verify cipher dispatch. */
  const struct {
    CryptoAlgorithm algorithm;
    unsigned char key[16], plain[16], expected[16];
  } cases[] = {{CRYPTO_XTEA128_CBC,
                {0x27, 0xf9, 0x17, 0xb1, 0xc1, 0xda, 0x89, 0x93, 0x60, 0xe2, 0xac, 0xaa, 0xa6, 0xeb,
                 0x92, 0x3d},
                {0xaf, 0x20, 0xa3, 0x90, 0x54, 0x75, 0x71, 0xaa},
                {0xd2, 0x64, 0x28, 0xaf, 0x0a, 0x20, 0x22, 0x83}},
               {CRYPTO_RC5128_CBC,
                {0x91, 0x5f, 0x46, 0x19, 0xbe, 0x41, 0xb2, 0x51, 0x63, 0x55, 0xa5, 0x01, 0x10, 0xa9,
                 0xce, 0x91},
                {0x21, 0xa5, 0xdb, 0xee, 0x15, 0x4b, 0x8f, 0x6d},
                {0xf7, 0xc0, 0x13, 0xac, 0x5b, 0x2b, 0x89, 0x52}},
               {CRYPTO_RC6128_CBC,
                {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56,
                 0x67, 0x78},
                {0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf,
                 0xe0, 0xf1},
                {0x52, 0x4e, 0x19, 0x2f, 0x47, 0x15, 0xc6, 0x23, 0x1f, 0x51, 0xf6, 0x36, 0x7e, 0xa4,
                 0x3f, 0x18}},
               {CRYPTO_SKIPJACK80_CBC,
                {0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11},
                {0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa},
                {0x25, 0x87, 0xca, 0xe2, 0x7a, 0x12, 0xd3, 0x00}},
               {CRYPTO_CAMELLIA128_CBC,
                {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                 0x32, 0x10},
                {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                 0x32, 0x10},
                {0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea,
                 0xbe, 0x43}},
               {CRYPTO_SPECK128_CBC,
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                 0x0e, 0x0f},
                {0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74, 0x20, 0x65, 0x71, 0x75, 0x69, 0x76,
                 0x61, 0x6c},
                {0x18, 0x0d, 0x57, 0x5c, 0xdf, 0xfe, 0x60, 0x78, 0x65, 0x32, 0x78, 0x79, 0x51, 0x98,
                 0x5d, 0xa6}},
               {CRYPTO_MARS128_CBC,
                {0},
                {0},
                {0xdc, 0xc0, 0x7b, 0x8d, 0xfb, 0x07, 0x38, 0xd6, 0xe3, 0x0a, 0x22, 0xdf, 0xcf, 0x27,
                 0xe8, 0x86}},
               {CRYPTO_SAFERK64_CBC,
                {8, 7, 6, 5, 4, 3, 2, 1},
                {1, 2, 3, 4, 5, 6, 7, 8},
                {0xc8, 0xf2, 0x9c, 0xdd, 0x87, 0x78, 0x3e, 0xd9}},
               {CRYPTO_FEAL8_CBC,
                {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
                {0},
                {0xce, 0xef, 0x2c, 0x86, 0xf2, 0x49, 0x07, 0x52}}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    unsigned char iv[16] = {0}, encrypted[32], restored[32];
    ULONG block_size = crypto_algorithm_info(cases[i].algorithm)->block_size;
    CryptoContext context;
    ULONG encrypted_size, restored_size;
    assert(crypto_init(&context, cases[i].algorithm));
    memcpy(context.portable_key, cases[i].key, sizeof(cases[i].key));
    if (cases[i].algorithm == CRYPTO_SAFERK64_CBC)
      safer_expand_key(context.portable_key, context.safer_schedule);
    if (cases[i].algorithm == CRYPTO_FEAL8_CBC)
      feal8_expand_key(context.portable_key, context.feal8_schedule);
    assert(crypto_encrypt(&context, iv, cases[i].plain, block_size, encrypted, sizeof(encrypted),
                          &encrypted_size));
    assert(encrypted_size == 2 * block_size &&
           memcmp(encrypted, cases[i].expected, block_size) == 0);
    assert(crypto_decrypt(&context, iv, encrypted, encrypted_size, restored, sizeof(restored),
                          &restored_size));
    assert(restored_size == block_size && memcmp(restored, cases[i].plain, block_size) == 0);
    /* Exercise the separately dispatched streaming path with split blocks. */
    {
      CryptoStream stream;
      unsigned char chunked[32];
      ULONG part, offset = 0;
      assert(crypto_stream_init(&stream, &context, true, iv));
      assert(crypto_stream_update(&stream, cases[i].plain, 1, chunked, sizeof(chunked), &part));
      offset += part;
      assert(crypto_stream_update(&stream, cases[i].plain + 1, block_size - 1,
                                  chunked + offset, sizeof(chunked) - offset, &part));
      offset += part;
      assert(crypto_stream_final(&stream, chunked + offset, sizeof(chunked) - offset, &part));
      offset += part;
      assert(offset == encrypted_size && memcmp(chunked, encrypted, offset) == 0);
      crypto_stream_close(&stream);

      assert(crypto_stream_init(&stream, &context, false, iv));
      offset = 0;
      for (ULONG byte = 0; byte < encrypted_size; ++byte) {
        assert(crypto_stream_update(&stream, encrypted + byte, 1, chunked + offset,
                                    sizeof(chunked) - offset, &part));
        offset += part;
      }
      assert(crypto_stream_final(&stream, chunked + offset, sizeof(chunked) - offset, &part));
      offset += part;
      assert(offset == block_size && memcmp(chunked, cases[i].plain, offset) == 0);
      crypto_stream_close(&stream);
    }
    crypto_close(&context);
    for (size_t byte = 0; byte < sizeof(context.safer_schedule); ++byte)
      assert(context.safer_schedule[byte] == 0);
    for (size_t byte = 0; byte < sizeof(context.feal8_schedule); ++byte)
      assert(context.feal8_schedule[byte] == 0);
  }
}

static void check_stream_dispatch(void) {
  const unsigned char key[8] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
  const unsigned char expected[14] = {0xcb, 0xa2, 0x55, 0x76, 0x17, 0x5d, 0x3b,
                                      0x1c, 0x7b, 0x2f, 0x29, 0xa8, 0xc1, 0xb6};
  unsigned char iv[16] = {0}, plain[14] = {0}, cipher[14], restored[14];
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
    check_algorithm(info->id, false);
    check_algorithm(info->id, true);
    printf("%s: streaming tree restoration, authentication, and expiry passed.\n", info->name);
  }
  return 0;
}
