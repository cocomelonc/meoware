#include "crypto.h"

#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

bool crypto_random(unsigned char *buffer, ULONG length) {
  return buffer != NULL &&
       BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer, length,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool crypto_init(CryptoContext *context) {
  NTSTATUS status;
  ULONG result_size = 0;
  unsigned char key_bytes[AES_KEY_SIZE];

  if (context == NULL) {
    return false;
  }
  memset(context, 0, sizeof(*context));
  memset(key_bytes, 0, sizeof(key_bytes));

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
  context->key_object_size = 0;
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

  if (context == NULL || context->key == NULL || iv == NULL ||
    (input == NULL && input_size != 0) || output == NULL ||
    output_size == NULL || input_size > output_capacity) {
    return false;
  }

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
