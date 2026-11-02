/* author: cocomelonc */
#include "crypto.h"
#include "cbc.h"

#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

_Static_assert(TEA_KEY_SIZE == XTEA_KEY_SIZE && TEA_KEY_SIZE == RC5_KEY_SIZE &&
                   TEA_KEY_SIZE == RC6_KEY_SIZE,
               "Portable key storage must fit each cipher");
_Static_assert(A51_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit A5/1");
_Static_assert(SKIPJACK_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit Skipjack");
_Static_assert(CAMELLIA_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit Camellia");
_Static_assert(SPECK_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit Speck");
_Static_assert(MARS_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit MARS");
_Static_assert(SAFER_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit SAFER");
_Static_assert(FEAL8_KEY_SIZE <= TEA_KEY_SIZE, "Portable key storage must fit FEAL-8");

static const CryptoInfo algorithms[] = {
    {CRYPTO_AES256_CBC, "AES-256-CBC", AES_KEY_SIZE, AES_BLOCK_SIZE, AES_BLOCK_SIZE},
    {CRYPTO_TEA128_CBC, "TEA-128-CBC", TEA_KEY_SIZE, TEA_BLOCK_SIZE, TEA_BLOCK_SIZE},
    {CRYPTO_XTEA128_CBC, "XTEA-128-CBC", XTEA_KEY_SIZE, XTEA_BLOCK_SIZE, XTEA_BLOCK_SIZE},
    {CRYPTO_RC5128_CBC, "RC5-128-CBC", RC5_KEY_SIZE, RC5_BLOCK_SIZE, RC5_BLOCK_SIZE},
    {CRYPTO_RC6128_CBC, "RC6-128-CBC", RC6_KEY_SIZE, RC6_BLOCK_SIZE, RC6_BLOCK_SIZE},
    {CRYPTO_A51, "A5/1", A51_KEY_SIZE, 0, A51_IV_SIZE},
    {CRYPTO_SKIPJACK80_CBC, "Skipjack-80-CBC", SKIPJACK_KEY_SIZE, SKIPJACK_BLOCK_SIZE,
     SKIPJACK_BLOCK_SIZE},
    {CRYPTO_CAMELLIA128_CBC, "Camellia-128-CBC", CAMELLIA_KEY_SIZE, CAMELLIA_BLOCK_SIZE,
     CAMELLIA_BLOCK_SIZE},
    {CRYPTO_SPECK128_CBC, "Speck-128-CBC", SPECK_KEY_SIZE, SPECK_BLOCK_SIZE, SPECK_BLOCK_SIZE},
    {CRYPTO_MARS128_CBC, "MARS-128-CBC", MARS_KEY_SIZE, MARS_BLOCK_SIZE, MARS_BLOCK_SIZE},
    {CRYPTO_SAFERK64_CBC, "SAFER-K64-CBC", SAFER_KEY_SIZE, SAFER_BLOCK_SIZE, SAFER_BLOCK_SIZE},
    {CRYPTO_FEAL8_CBC, "FEAL-8-CBC", FEAL8_KEY_SIZE, FEAL8_BLOCK_SIZE, FEAL8_BLOCK_SIZE}};

size_t crypto_algorithm_count(void) {
  return sizeof(algorithms) / sizeof(algorithms[0]);
}

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
         BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
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
    if (!crypto_random(context->portable_key, crypto_algorithm_info(selected)->key_size))
      goto failure;
    if (selected == CRYPTO_SAFERK64_CBC)
      safer_expand_key(context->portable_key, context->safer_schedule);
    if (selected == CRYPTO_FEAL8_CBC)
      feal8_expand_key(context->portable_key, context->feal8_schedule);
    context->initialized = true;
    return true;
  }

  status = BCryptOpenAlgorithmProvider(&context->algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status)) {
    goto failure;
  }

  status = BCryptSetProperty(context->algorithm, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!BCRYPT_SUCCESS(status)) {
    goto failure;
  }

  status =
      BCryptGetProperty(context->algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&context->key_object_size,
                        sizeof(context->key_object_size), &result_size, 0);
  if (!BCRYPT_SUCCESS(status) || context->key_object_size == 0) {
    goto failure;
  }

  context->key_object = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, context->key_object_size);
  if (context->key_object == NULL || !crypto_random(key_bytes, sizeof(key_bytes))) {
    goto failure;
  }

  status = BCryptGenerateSymmetricKey(context->algorithm, &context->key, context->key_object,
                                      context->key_object_size, key_bytes, sizeof(key_bytes), 0);
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

static bool crypt_buffer(CryptoContext *context, bool encrypt, const unsigned char iv[16],
                         const unsigned char *input, ULONG input_size, unsigned char *output,
                         ULONG output_capacity, ULONG *output_size) {
  unsigned char iv_copy[AES_BLOCK_SIZE];
  NTSTATUS status;
  CbcBlockTransform transform = NULL;
  const unsigned char *transform_key;

  if (output_size != NULL) *output_size = 0;
  if (context == NULL || !context->initialized || iv == NULL ||
      (input == NULL && input_size != 0) || output == NULL || output_size == NULL ||
      input_size > output_capacity) {
    return false;
  }

  transform_key = context->portable_key;
  switch (context->selected) {
    case CRYPTO_A51: {
      uint32_t frame = (uint32_t)iv[0] | ((uint32_t)iv[1] << 8) | ((uint32_t)iv[2] << 16);
      size_t written = 0;
      bool success = a51_crypt(context->portable_key, frame, input, input_size, output,
                               output_capacity, &written);
      if (success) *output_size = (ULONG)written;
      return success;
    }
    case CRYPTO_TEA128_CBC:
      transform = encrypt ? tea_encrypt_block : tea_decrypt_block;
      break;
    case CRYPTO_XTEA128_CBC:
      transform = encrypt ? xtea_encrypt_block : xtea_decrypt_block;
      break;
    case CRYPTO_RC5128_CBC:
      transform = encrypt ? rc5_encrypt_block : rc5_decrypt_block;
      break;
    case CRYPTO_RC6128_CBC:
      transform = encrypt ? rc6_encrypt_block : rc6_decrypt_block;
      break;
    case CRYPTO_SKIPJACK80_CBC:
      transform = encrypt ? skipjack_encrypt_block : skipjack_decrypt_block;
      break;
    case CRYPTO_CAMELLIA128_CBC:
      transform = encrypt ? camellia_encrypt_block : camellia_decrypt_block;
      break;
    case CRYPTO_SPECK128_CBC:
      transform = encrypt ? speck_encrypt_block : speck_decrypt_block;
      break;
    case CRYPTO_MARS128_CBC:
      transform = encrypt ? mars_encrypt_block : mars_decrypt_block;
      break;
    case CRYPTO_SAFERK64_CBC:
      transform = encrypt ? safer_encrypt_prepared : safer_decrypt_prepared;
      transform_key = context->safer_schedule;
      break;
    case CRYPTO_FEAL8_CBC:
      transform = encrypt ? feal8_encrypt_prepared : feal8_decrypt_prepared;
      transform_key = context->feal8_schedule;
      break;
    default:
      break;
  }
  if (transform != NULL) {
    size_t written = 0;
    size_t block_size = crypto_algorithm_info(context->selected)->block_size;
    bool success = encrypt ? cbc_encrypt(transform, block_size, transform_key, iv, input,
                                         input_size, output, output_capacity, &written)
                           : cbc_decrypt(transform, block_size, transform_key, iv, input,
                                         input_size, output, output_capacity, &written);
    if (success) *output_size = (ULONG)written;
    return success;
  }
  if (context->selected != CRYPTO_AES256_CBC || context->key == NULL) return false;

  memcpy(iv_copy, iv, sizeof(iv_copy));
  if (encrypt) {
    status = BCryptEncrypt(context->key, (PUCHAR)input, input_size, NULL, iv_copy, sizeof(iv_copy),
                           output, output_capacity, output_size, BCRYPT_BLOCK_PADDING);
  } else {
    if (input_size == 0 || input_size % AES_BLOCK_SIZE != 0) {
      SecureZeroMemory(iv_copy, sizeof(iv_copy));
      return false;
    }
    status = BCryptDecrypt(context->key, (PUCHAR)input, input_size, NULL, iv_copy, sizeof(iv_copy),
                           output, output_capacity, output_size, BCRYPT_BLOCK_PADDING);
  }

  SecureZeroMemory(iv_copy, sizeof(iv_copy));
  return BCRYPT_SUCCESS(status);
}

bool crypto_encrypt(CryptoContext *context, const unsigned char iv[16], const unsigned char *input,
                    ULONG input_size, unsigned char *output, ULONG output_capacity,
                    ULONG *output_size) {
  return crypt_buffer(context, true, iv, input, input_size, output, output_capacity, output_size);
}

bool crypto_decrypt(CryptoContext *context, const unsigned char iv[16], const unsigned char *input,
                    ULONG input_size, unsigned char *output, ULONG output_capacity,
                    ULONG *output_size) {
  return crypt_buffer(context, false, iv, input, input_size, output, output_capacity, output_size);
}

static bool crypto_transform_block(CryptoContext *context, bool encrypt,
                                   unsigned char block[CRYPTO_MAX_BLOCK_SIZE]) {
  CbcBlockTransform transform = NULL;
  const unsigned char *transform_key;
  unsigned char result[CRYPTO_MAX_BLOCK_SIZE];
  unsigned char zero_iv[CRYPTO_MAX_BLOCK_SIZE] = {0};
  ULONG result_size = 0;
  NTSTATUS status;

  if (context == NULL || !context->initialized || block == NULL) return false;
  transform_key = context->portable_key;
  switch (context->selected) {
    case CRYPTO_TEA128_CBC:
      transform = encrypt ? tea_encrypt_block : tea_decrypt_block;
      break;
    case CRYPTO_XTEA128_CBC:
      transform = encrypt ? xtea_encrypt_block : xtea_decrypt_block;
      break;
    case CRYPTO_RC5128_CBC:
      transform = encrypt ? rc5_encrypt_block : rc5_decrypt_block;
      break;
    case CRYPTO_RC6128_CBC:
      transform = encrypt ? rc6_encrypt_block : rc6_decrypt_block;
      break;
    case CRYPTO_SKIPJACK80_CBC:
      transform = encrypt ? skipjack_encrypt_block : skipjack_decrypt_block;
      break;
    case CRYPTO_CAMELLIA128_CBC:
      transform = encrypt ? camellia_encrypt_block : camellia_decrypt_block;
      break;
    case CRYPTO_SPECK128_CBC:
      transform = encrypt ? speck_encrypt_block : speck_decrypt_block;
      break;
    case CRYPTO_MARS128_CBC:
      transform = encrypt ? mars_encrypt_block : mars_decrypt_block;
      break;
    case CRYPTO_SAFERK64_CBC:
      transform = encrypt ? safer_encrypt_prepared : safer_decrypt_prepared;
      transform_key = context->safer_schedule;
      break;
    case CRYPTO_FEAL8_CBC:
      transform = encrypt ? feal8_encrypt_prepared : feal8_decrypt_prepared;
      transform_key = context->feal8_schedule;
      break;
    case CRYPTO_AES256_CBC:
      if (context->key == NULL) return false;
      status = encrypt ? BCryptEncrypt(context->key, block, AES_BLOCK_SIZE, NULL, zero_iv,
                                       sizeof(zero_iv), result, AES_BLOCK_SIZE, &result_size, 0)
                       : BCryptDecrypt(context->key, block, AES_BLOCK_SIZE, NULL, zero_iv,
                                       sizeof(zero_iv), result, AES_BLOCK_SIZE, &result_size, 0);
      if (!BCRYPT_SUCCESS(status) || result_size != AES_BLOCK_SIZE) {
        SecureZeroMemory(result, sizeof(result));
        SecureZeroMemory(zero_iv, sizeof(zero_iv));
        return false;
      }
      memcpy(block, result, AES_BLOCK_SIZE);
      SecureZeroMemory(result, sizeof(result));
      SecureZeroMemory(zero_iv, sizeof(zero_iv));
      return true;
    default:
      return false;
  }
  if (transform == NULL) return false;
  transform(block, transform_key);
  return true;
}

bool crypto_stream_init(CryptoStream *stream, CryptoContext *context, bool encrypt,
                        const unsigned char iv[16]) {
  const CryptoInfo *info;
  if (stream == NULL || context == NULL || !context->initialized || iv == NULL) return false;
  memset(stream, 0, sizeof(*stream));
  info = crypto_algorithm_info(context->selected);
  if (info == NULL) return false;
  stream->crypto = context;
  stream->encrypt = encrypt;
  stream->block_size = info->block_size;
  if (context->selected == CRYPTO_A51) {
    uint32_t frame = (uint32_t)iv[0] | ((uint32_t)iv[1] << 8) | ((uint32_t)iv[2] << 16);
    if ((iv[2] & 0xc0) != 0 || !a51_stream_init(&stream->a51, context->portable_key, frame)) {
      SecureZeroMemory(stream, sizeof(*stream));
      return false;
    }
  } else {
    if (stream->block_size != 8 && stream->block_size != 16) {
      SecureZeroMemory(stream, sizeof(*stream));
      return false;
    }
    memcpy(stream->chain, iv, stream->block_size);
  }
  stream->initialized = true;
  return true;
}

static bool crypto_stream_process_block(CryptoStream *stream, unsigned char *output) {
  unsigned char block[CRYPTO_MAX_BLOCK_SIZE];
  unsigned char saved[CRYPTO_MAX_BLOCK_SIZE];
  size_t index;
  bool success;

  if (stream == NULL || output == NULL || stream->pending_size != stream->block_size) return false;
  memcpy(block, stream->pending, stream->block_size);
  if (stream->encrypt) {
    for (index = 0; index < stream->block_size; ++index) block[index] ^= stream->chain[index];
    success = crypto_transform_block(stream->crypto, true, block);
    if (success) {
      memcpy(stream->chain, block, stream->block_size);
      memcpy(output, block, stream->block_size);
    }
  } else {
    memcpy(saved, block, stream->block_size);
    success = crypto_transform_block(stream->crypto, false, block);
    if (success) {
      for (index = 0; index < stream->block_size; ++index) block[index] ^= stream->chain[index];
      memcpy(stream->chain, saved, stream->block_size);
      memcpy(output, block, stream->block_size);
    }
  }
  SecureZeroMemory(block, sizeof(block));
  SecureZeroMemory(saved, sizeof(saved));
  if (success) {
    SecureZeroMemory(stream->pending, sizeof(stream->pending));
    stream->pending_size = 0;
  }
  return success;
}

bool crypto_stream_update(CryptoStream *stream, const unsigned char *input, ULONG input_size,
                          unsigned char *output, ULONG output_capacity, ULONG *output_size) {
  size_t input_offset = 0;
  size_t written = 0;
  size_t total;
  size_t blocks;
  size_t required;

  if (output_size == NULL) return false;
  *output_size = 0;
  if (stream == NULL || !stream->initialized || stream->finalized ||
      (input == NULL && input_size != 0) || output == NULL)
    return false;
  if (stream->block_size == 0) {
    size_t written = 0;
    if (!a51_stream_crypt(&stream->a51, input, input_size, output, output_capacity, &written))
      return false;
    *output_size = (ULONG)written;
    return true;
  }

  total = stream->pending_size + (size_t)input_size;
  if (stream->encrypt) {
    blocks = total / stream->block_size;
  } else {
    /* Keep one complete ciphertext block until final() can validate padding. */
    blocks = total > stream->block_size ? (total - 1) / stream->block_size : 0;
  }
  required = blocks * stream->block_size;
  if (required > output_capacity) return false;

  while (input_offset < input_size) {
    if (!stream->encrypt && stream->pending_size == stream->block_size) {
      if (!crypto_stream_process_block(stream, output + written)) return false;
      written += stream->block_size;
    }
    {
      size_t available = stream->block_size - stream->pending_size;
      size_t remaining = (size_t)input_size - input_offset;
      size_t take = available < remaining ? available : remaining;
      memcpy(stream->pending + stream->pending_size, input + input_offset, take);
      stream->pending_size += take;
      input_offset += take;
    }
    if (stream->encrypt && stream->pending_size == stream->block_size) {
      if (!crypto_stream_process_block(stream, output + written)) return false;
      written += stream->block_size;
    }
  }
  *output_size = (ULONG)written;
  return true;
}

bool crypto_stream_final(CryptoStream *stream, unsigned char *output, ULONG output_capacity,
                         ULONG *output_size) {
  unsigned int padding;
  unsigned int invalid;
  size_t index;

  if (output_size == NULL) return false;
  *output_size = 0;
  if (stream == NULL || !stream->initialized || stream->finalized || output == NULL) return false;
  if (stream->block_size == 0) {
    if (stream->pending_size != 0) return false;
    stream->finalized = true;
    return true;
  }
  if (output_capacity < stream->block_size) return false;
  if (stream->encrypt) {
    padding = (unsigned int)(stream->block_size - stream->pending_size);
    memset(stream->pending + stream->pending_size, (int)padding, padding);
    stream->pending_size = stream->block_size;
    if (!crypto_stream_process_block(stream, output)) return false;
    *output_size = (ULONG)stream->block_size;
  } else {
    unsigned char block[CRYPTO_MAX_BLOCK_SIZE];
    unsigned char saved[CRYPTO_MAX_BLOCK_SIZE];
    if (stream->pending_size != stream->block_size) return false;
    memcpy(block, stream->pending, stream->block_size);
    memcpy(saved, block, stream->block_size);
    if (!crypto_transform_block(stream->crypto, false, block)) {
      SecureZeroMemory(block, sizeof(block));
      SecureZeroMemory(saved, sizeof(saved));
      return false;
    }
    for (index = 0; index < stream->block_size; ++index) block[index] ^= stream->chain[index];
    padding = block[stream->block_size - 1];
    invalid = padding == 0 || padding > stream->block_size;
    for (index = 0; index < stream->block_size; ++index) {
      unsigned int selected = (unsigned int)(index < padding);
      if (selected && block[stream->block_size - 1 - index] != (unsigned char)padding) invalid = 1;
    }
    if (invalid) {
      SecureZeroMemory(block, sizeof(block));
      SecureZeroMemory(saved, sizeof(saved));
      return false;
    }
    *output_size = (ULONG)(stream->block_size - padding);
    if (*output_size != 0) memcpy(output, block, *output_size);
    SecureZeroMemory(block, sizeof(block));
    SecureZeroMemory(saved, sizeof(saved));
    SecureZeroMemory(stream->pending, sizeof(stream->pending));
    stream->pending_size = 0;
  }
  stream->finalized = true;
  return true;
}

void crypto_stream_close(CryptoStream *stream) {
  if (stream == NULL) return;
  a51_stream_close(&stream->a51);
  SecureZeroMemory(stream, sizeof(*stream));
}

bool crypto_mac_init(CryptoMacContext *context, const unsigned char *key, ULONG key_size) {
  ULONG result_size = 0;
  NTSTATUS status;
  if (context == NULL || key == NULL || key_size == 0) return false;
  memset(context, 0, sizeof(*context));
  status = BCryptOpenAlgorithmProvider(&context->algorithm, BCRYPT_SHA256_ALGORITHM, NULL,
                                       BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!BCRYPT_SUCCESS(status)) goto failure;
  status = BCryptGetProperty(context->algorithm, BCRYPT_OBJECT_LENGTH,
                             (PUCHAR)&context->object_size, sizeof(context->object_size),
                             &result_size, 0);
  if (!BCRYPT_SUCCESS(status) || context->object_size == 0) goto failure;
  context->object = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, context->object_size);
  if (context->object == NULL) goto failure;
  status = BCryptCreateHash(context->algorithm, &context->hash, context->object,
                            context->object_size, (PUCHAR)key, key_size, 0);
  if (!BCRYPT_SUCCESS(status)) goto failure;
  context->initialized = true;
  return true;

failure:
  crypto_mac_close(context);
  return false;
}

bool crypto_mac_update(CryptoMacContext *context, const unsigned char *data, ULONG size) {
  if (context == NULL || !context->initialized || (data == NULL && size != 0)) return false;
  return BCRYPT_SUCCESS(BCryptHashData(context->hash, (PUCHAR)data, size, 0));
}

bool crypto_mac_final(CryptoMacContext *context, unsigned char mac[CRYPTO_MAC_SIZE]) {
  if (context == NULL || !context->initialized || mac == NULL) return false;
  return BCRYPT_SUCCESS(BCryptFinishHash(context->hash, mac, CRYPTO_MAC_SIZE, 0));
}

void crypto_mac_close(CryptoMacContext *context) {
  if (context == NULL) return;
  if (context->hash != NULL) {
    BCryptDestroyHash(context->hash);
    context->hash = NULL;
  }
  if (context->object != NULL) {
    SecureZeroMemory(context->object, context->object_size);
    HeapFree(GetProcessHeap(), 0, context->object);
    context->object = NULL;
  }
  if (context->algorithm != NULL) {
    BCryptCloseAlgorithmProvider(context->algorithm, 0);
    context->algorithm = NULL;
  }
  SecureZeroMemory(context, sizeof(*context));
}
