/* Native OpenSSL backend, shared streaming and Linux filesystem regression. */
#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "linux_lab.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  /* RFC 4231, HMAC-SHA-256 test case 1. */
  const unsigned char expected_mac[32] = {
    0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
    0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
  unsigned char key[20], tag[32];
  memset(key, 0x0b, sizeof(key));
  CryptoMacContext mac = {0};
  assert(crypto_mac_init(&mac, key, sizeof(key)));
  assert(crypto_mac_update(&mac, (const unsigned char *)"Hi ", 3));
  assert(crypto_mac_update(&mac, (const unsigned char *)"There", 5));
  assert(crypto_mac_final(&mac, tag));
  assert(memcmp(tag, expected_mac, sizeof(tag)) == 0);
  crypto_mac_close(&mac);

  /* NIST SP 800-38A F.2.5, AES-256-CBC first block (padding adds another block). */
  const unsigned char aes_key[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
  const unsigned char plain[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
  const unsigned char expected[16] = {0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6};
  unsigned char iv[16], output[64], streamed[64], decoded[64];
  for (size_t i = 0; i < sizeof(iv); ++i) iv[i] = (unsigned char)i;
  CryptoContext aes;
  ULONG size = 0, part = 0, total = 0;
  assert(crypto_init(&aes, CRYPTO_AES256_CBC));
  memcpy(aes.aes_key, aes_key, sizeof(aes_key));
  assert(EVP_EncryptInit_ex(aes.aes_encrypt, NULL, NULL, aes_key, NULL) == 1);
  assert(EVP_DecryptInit_ex(aes.aes_decrypt, NULL, NULL, aes_key, NULL) == 1);
  assert(crypto_encrypt(&aes, iv, plain, sizeof(plain), output, sizeof(output), &size));
  assert(size == 32 && memcmp(output, expected, 16) == 0);
  CryptoStream stream;
  assert(crypto_stream_init(&stream, &aes, true, iv));
  assert(crypto_stream_update(&stream, plain, 1, streamed, sizeof(streamed), &part)); total += part;
  assert(crypto_stream_update(&stream, plain + 1, 15, streamed + total, sizeof(streamed)-total, &part)); total += part;
  assert(crypto_stream_final(&stream, streamed + total, sizeof(streamed)-total, &part)); total += part;
  assert(total == size && memcmp(output, streamed, size) == 0);
  crypto_stream_close(&stream);
  assert(crypto_decrypt(&aes, iv, streamed, total, decoded, sizeof(decoded), &part));
  assert(part == sizeof(plain) && memcmp(decoded, plain, part) == 0);
  crypto_close(&aes);
  puts("AES-256-CBC and HMAC-SHA-256 independent known answers passed.");

  unsigned char *data = malloc(131089), *restored = malloc(131089);
  assert(data && restored);
  for (size_t i = 0; i < 131089; ++i) data[i] = (unsigned char)(i * 31U + 17U);
  for (size_t i = 0; i < crypto_algorithm_count(); ++i) {
    char error[512], path[4096], directory[4096];
    const CryptoInfo *info = crypto_algorithm_at(i);
    LinuxLab *lab = linux_lab_new(error, sizeof(error));
    assert(lab);
    snprintf(directory, sizeof(directory), "%s", linux_lab_directory(lab));
    assert(snprintf(path, sizeof(path), "%s/payload.bin", directory) > 0);
    FILE *f = fopen(path, "wb");
    assert(f && fwrite(data, 1, 131089, f) == 131089 && fclose(f) == 0);
    assert(linux_lab_encrypt(lab, info->id, error, sizeof(error)));
    assert(linux_lab_restore(lab, error, sizeof(error)));
    f = fopen(path, "rb");
    assert(f && fread(restored, 1, 131089, f) == 131089 && fgetc(f) == EOF && fclose(f) == 0);
    assert(memcmp(data, restored, 131089) == 0);
    linux_lab_free(lab);
    assert(unlink(path) == 0 && rmdir(directory) == 0);
    printf("%s: native streaming restoration passed.\n", info->name);
  }
  free(data);
  free(restored);
  return 0;
}
