/* author: cocomelonc */
#include "crypto.h"
#include "cbc.h"

#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

_Static_assert(TEA_KEY_SIZE == XTEA_KEY_SIZE && TEA_KEY_SIZE == RC5_KEY_SIZE && TEA_KEY_SIZE == RC6_KEY_SIZE,
  "Portable key storage must fit each cipher");
_Static_assert(A51_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit A5/1");
_Static_assert(SKIPJACK_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit Skipjack");
_Static_assert(CAMELLIA_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit Camellia");

static const CryptoInfo algorithms[] = {
  { CRYPTO_AES256_CBC, "AES-256-CBC", AES_KEY_SIZE, AES_BLOCK_SIZE, AES_BLOCK_SIZE },
  { CRYPTO_TEA128_CBC, "TEA-128-CBC", TEA_KEY_SIZE, TEA_BLOCK_SIZE, TEA_BLOCK_SIZE },
  { CRYPTO_XTEA128_CBC, "XTEA-128-CBC", XTEA_KEY_SIZE, XTEA_BLOCK_SIZE, XTEA_BLOCK_SIZE },
  { CRYPTO_RC5128_CBC, "RC5-128-CBC", RC5_KEY_SIZE, RC5_BLOCK_SIZE, RC5_BLOCK_SIZE },
  { CRYPTO_RC6128_CBC, "RC6-128-CBC", RC6_KEY_SIZE, RC6_BLOCK_SIZE, RC6_BLOCK_SIZE },
  { CRYPTO_A51, "A5/1", A51_KEY_SIZE, 0, A51_IV_SIZE },
  { CRYPTO_SKIPJACK80_CBC, "Skipjack-80-CBC", SKIPJACK_KEY_SIZE, SKIPJACK_BLOCK_SIZE, SKIPJACK_BLOCK_SIZE },
  { CRYPTO_CAMELLIA128_CBC, "Camellia-128-CBC", CAMELLIA_KEY_SIZE, CAMELLIA_BLOCK_SIZE, CAMELLIA_BLOCK_SIZE }
};

size_t crypto_algorithm_count(void) { return sizeof(algorithms) / sizeof(algorithms[0]); }

const CryptoInfo *crypto_algorithm_at(size_t index) {
  return index < crypto_algorithm_count() ? &algorithms[index] : NULL;
}

const CryptoInfo *crypto_algorithm_info(CryptoAlgorithm id) {
  size_t index;
  for (index = 0; index < crypto_algorithm_count(); ++index) {
    if (algorithms[index].id == id) return &algorithms[index];
  }
  return NULL;
}

bool crypto_random(unsigned char *buffer, ULONG length) {
  return buffer != NULL &&
       BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer, length,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool crypto_init(CryptoContext *context, CryptoAlgorithm selected) {
  NTSTATUS status;
  ULONG result_size = 0;
  unsigned char key_bytes[AES_KEY_SIZE];

  if (context == NULL) {
    return false;
  }
  memset(context, 0, sizeof(*context));
  memset(key_bytes, 0, sizeof(key_bytes));
  if (crypto_algorithm_info(selected) == NULL) return false;
  context->selected = selected;
  if (selected != CRYPTO_AES256_CBC) {
    if (!crypto_random(context->portable_key, crypto_algorithm_info(selected)->key_size)) goto failure;
    context->initialized = true;
    return true;
  }

  status = BCryptOpenAlgorithmProvider(&context->algorithm,
                     BCRYPT_AES_ALGORITHM,
                     NULL,
                     0);
  if (!BCRYPT_SUCCESS(status)) {
    goto failure;
  }

  status = BCryptSetProperty(context->algorithm,
                 BCRYPT_CHAINING_MODE,
                 (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                 sizeof(BCRYPT_CHAIN_MODE_CBC),
                 0);
  if (!BCRYPT_SUCCESS(status)) {
    goto failure;
  }

  status = BCryptGetProperty(context->algorithm,
                 BCRYPT_OBJECT_LENGTH,
                 (PUCHAR)&context->key_object_size,
                 sizeof(context->key_object_size),
                 &result_size,
                 0);
  if (!BCRYPT_SUCCESS(status) || context->key_object_size == 0) {
    goto failure;
  }

  context->key_object = (unsigned char *)HeapAlloc(
    GetProcessHeap(), 0, context->key_object_size);
  if (context->key_object == NULL || !crypto_random(key_bytes, sizeof(key_bytes))) {
    goto failure;
  }

  status = BCryptGenerateSymmetricKey(context->algorithm,
                    &context->key,
                    context->key_object,
                    context->key_object_size,
                    key_bytes,
                    sizeof(key_bytes),
                    0);
  SecureZeroMemory(key_bytes, sizeof(key_bytes));
  if (!BCRYPT_SUCCESS(status)) {
    goto failure;
  }
  context->initialized = true;
  return true;

failure:
  SecureZeroMemory(key_bytes, sizeof(key_bytes));
  crypto_close(context);
  return false;
}

void crypto_close(CryptoContext *context) {
  if (context == NULL) {
    return;
  }
  if (context->key != NULL) {
    BCryptDestroyKey(context->key);
    context->key = NULL;
  }
  if (context->key_object != NULL) {
    SecureZeroMemory(context->key_object, context->key_object_size);
    HeapFree(GetProcessHeap(), 0, context->key_object);
    context->key_object = NULL;
  }
  if (context->algorithm != NULL) {
    BCryptCloseAlgorithmProvider(context->algorithm, 0);
    context->algorithm = NULL;
  }
  SecureZeroMemory(context, sizeof(*context));
}

static bool crypt_buffer(CryptoContext *context,
             bool encrypt,
             const unsigned char iv[16],
             const unsigned char *input,
             ULONG input_size,
             unsigned char *output,
             ULONG output_capacity,
             ULONG *output_size) {
  unsigned char iv_copy[AES_BLOCK_SIZE];
  NTSTATUS status;
  CbcBlockTransform transform = NULL;

  if (output_size != NULL) *output_size = 0;
  if (context == NULL || !context->initialized || iv == NULL ||
    (input == NULL && input_size != 0) || output == NULL ||
    output_size == NULL || input_size > output_capacity) {
    return false;
  }

  switch (context->selected) {
  case CRYPTO_A51: {
    uint32_t frame = (uint32_t)iv[0] | ((uint32_t)iv[1] << 8) | ((uint32_t)iv[2] << 16);
    size_t written = 0;
    bool success = a51_crypt(context->portable_key, frame, input, input_size, output, output_capacity, &written);
    if (success) *output_size = (ULONG)written;
    return success;
  }
  case CRYPTO_TEA128_CBC: transform = encrypt ? tea_encrypt_block : tea_decrypt_block; break;
  case CRYPTO_XTEA128_CBC: transform = encrypt ? xtea_encrypt_block : xtea_decrypt_block; break;
  case CRYPTO_RC5128_CBC: transform = encrypt ? rc5_encrypt_block : rc5_decrypt_block; break;
  case CRYPTO_RC6128_CBC: transform = encrypt ? rc6_encrypt_block : rc6_decrypt_block; break;
  case CRYPTO_SKIPJACK80_CBC: transform = encrypt ? skipjack_encrypt_block : skipjack_decrypt_block; break;
  case CRYPTO_CAMELLIA128_CBC: transform = encrypt ? camellia_encrypt_block : camellia_decrypt_block; break;
  default: break;
  }
  if (transform != NULL) {
    size_t written = 0;
    size_t block_size = crypto_algorithm_info(context->selected)->block_size;
    bool success = encrypt
      ? cbc_encrypt(transform, block_size, context->portable_key, iv, input, input_size, output, output_capacity, &written)
      : cbc_decrypt(transform, block_size, context->portable_key, iv, input, input_size, output, output_capacity, &written);
    if (success) *output_size = (ULONG)written;
    return success;
  }
  if (context->selected != CRYPTO_AES256_CBC || context->key == NULL) return false;

  memcpy(iv_copy, iv, sizeof(iv_copy));
  if (encrypt) {
    status = BCryptEncrypt(context->key,
                 (PUCHAR)input,
                 input_size,
                 NULL,
                 iv_copy,
                 sizeof(iv_copy),
                 output,
                 output_capacity,
                 output_size,
                 BCRYPT_BLOCK_PADDING);
  } else {
    if (input_size == 0 || input_size % AES_BLOCK_SIZE != 0) {
      SecureZeroMemory(iv_copy, sizeof(iv_copy));
      return false;
    }
    status = BCryptDecrypt(context->key,
                 (PUCHAR)input,
                 input_size,
                 NULL,
                 iv_copy,
                 sizeof(iv_copy),
                 output,
                 output_capacity,
                 output_size,
                 BCRYPT_BLOCK_PADDING);
  }

  SecureZeroMemory(iv_copy, sizeof(iv_copy));
  return BCRYPT_SUCCESS(status);
}

bool crypto_encrypt(CryptoContext *context,
          const unsigned char iv[16],
          const unsigned char *input,
          ULONG input_size,
          unsigned char *output,
          ULONG output_capacity,
          ULONG *output_size) {
  return crypt_buffer(context, true, iv, input, input_size,
            output, output_capacity, output_size);
}

bool crypto_decrypt(CryptoContext *context,
          const unsigned char iv[16],
          const unsigned char *input,
          ULONG input_size,
          unsigned char *output,
          ULONG output_capacity,
          ULONG *output_size) {
  return crypt_buffer(context, false, iv, input, input_size,
            output, output_capacity, output_size);
}
