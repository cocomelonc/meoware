#ifndef MEOWARE_CRYPTO_H
#define MEOWARE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <bcrypt.h>
#include "tea.h"

#define CRYPTO_MAX_BLOCK_SIZE 16U

typedef enum {
    CRYPTO_AES256_CBC = 1,
    CRYPTO_TEA128_CBC = 2
} CryptoAlgorithm;

typedef struct {
    CryptoAlgorithm id;
    const char *name;
    unsigned int key_size;
    unsigned int block_size;
} CryptoInfo;

size_t crypto_algorithm_count(void);
const CryptoInfo *crypto_algorithm_at(size_t index);
const CryptoInfo *crypto_algorithm_info(CryptoAlgorithm id);

typedef struct {
    CryptoAlgorithm selected;
    bool initialized;
    unsigned char tea_key[TEA_KEY_SIZE];
    BCRYPT_ALG_HANDLE algorithm;
    BCRYPT_KEY_HANDLE key;
    unsigned char *key_object;
    ULONG key_object_size;
} CryptoContext;

bool crypto_init(CryptoContext *context, CryptoAlgorithm selected);
void crypto_close(CryptoContext *context);
bool crypto_random(unsigned char *buffer, ULONG length);
bool crypto_encrypt(CryptoContext *context,
                   const unsigned char iv[16],
                   const unsigned char *input,
                   ULONG input_size,
                   unsigned char *output,
                   ULONG output_capacity,
                   ULONG *output_size);
bool crypto_decrypt(CryptoContext *context,
                   const unsigned char iv[16],
                   const unsigned char *input,
                   ULONG input_size,
                   unsigned char *output,
                   ULONG output_capacity,
                   ULONG *output_size);

#endif
