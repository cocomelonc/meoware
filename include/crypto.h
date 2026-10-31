#ifndef MEOWARE_CRYPTO_H
#define MEOWARE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <bcrypt.h>
#include "tea.h"
#include "xtea.h"
#include "rc5.h"
#include "rc6.h"
#include "a51.h"
#include "skipjack.h"
#include "camellia.h"
#include "speck.h"
#include "mars.h"

#define CRYPTO_MAX_BLOCK_SIZE 16U
#define CRYPTO_MAC_SIZE 32U

typedef enum {
  CRYPTO_AES256_CBC = 1,
  CRYPTO_TEA128_CBC = 2,
  CRYPTO_XTEA128_CBC = 3,
  CRYPTO_RC5128_CBC = 4,
  CRYPTO_RC6128_CBC = 5,
  CRYPTO_A51 = 6,
  CRYPTO_SKIPJACK80_CBC = 7,
  CRYPTO_CAMELLIA128_CBC = 8,
  CRYPTO_SPECK128_CBC = 9,
  CRYPTO_MARS128_CBC = 10
} CryptoAlgorithm;

typedef struct {
  CryptoAlgorithm id;
  const char *name;
  unsigned int key_size;
  unsigned int block_size; /* Zero for a stream cipher. */
  unsigned int iv_size;
} CryptoInfo;

size_t crypto_algorithm_count(void);
const CryptoInfo *crypto_algorithm_at(size_t index);
const CryptoInfo *crypto_algorithm_info(CryptoAlgorithm id);

typedef struct {
  CryptoAlgorithm selected;
  bool initialized;
  unsigned char portable_key[TEA_KEY_SIZE];
  BCRYPT_ALG_HANDLE algorithm;
  BCRYPT_KEY_HANDLE key;
  unsigned char *key_object;
  ULONG key_object_size;
} CryptoContext;

typedef struct {
  CryptoContext *crypto;
  bool encrypt;
  bool initialized;
  bool finalized;
  size_t block_size;
  size_t pending_size;
  unsigned char chain[CRYPTO_MAX_BLOCK_SIZE];
  unsigned char pending[CRYPTO_MAX_BLOCK_SIZE];
  A51Stream a51;
} CryptoStream;

typedef struct {
  BCRYPT_ALG_HANDLE algorithm;
  BCRYPT_HASH_HANDLE hash;
  unsigned char *object;
  ULONG object_size;
  bool initialized;
} CryptoMacContext;

bool crypto_init(CryptoContext *context, CryptoAlgorithm selected);
void crypto_close(CryptoContext *context);
bool crypto_random(unsigned char *buffer, ULONG length);
bool crypto_encrypt(CryptoContext *context, const unsigned char iv[16], const unsigned char *input,
                    ULONG input_size, unsigned char *output, ULONG output_capacity,
                    ULONG *output_size);
bool crypto_decrypt(CryptoContext *context, const unsigned char iv[16], const unsigned char *input,
                    ULONG input_size, unsigned char *output, ULONG output_capacity,
                    ULONG *output_size);
bool crypto_stream_init(CryptoStream *stream, CryptoContext *context, bool encrypt,
                        const unsigned char iv[16]);
bool crypto_stream_update(CryptoStream *stream, const unsigned char *input, ULONG input_size,
                          unsigned char *output, ULONG output_capacity, ULONG *output_size);
bool crypto_stream_final(CryptoStream *stream, unsigned char *output, ULONG output_capacity,
                         ULONG *output_size);
void crypto_stream_close(CryptoStream *stream);

bool crypto_mac_init(CryptoMacContext *context, const unsigned char *key, ULONG key_size);
bool crypto_mac_update(CryptoMacContext *context, const unsigned char *data, ULONG size);
bool crypto_mac_final(CryptoMacContext *context, unsigned char mac[CRYPTO_MAC_SIZE]);
void crypto_mac_close(CryptoMacContext *context);

#endif
