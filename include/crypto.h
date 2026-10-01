#ifndef MEOWARE_CRYPTO_H
#define MEOWARE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <bcrypt.h>

typedef struct {
    BCRYPT_ALG_HANDLE algorithm;
    BCRYPT_KEY_HANDLE key;
    unsigned char *key_object;
    ULONG key_object_size;
} CryptoContext;

bool crypto_init(CryptoContext *context);
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
