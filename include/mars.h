#ifndef MEOWARE_MARS_H
#define MEOWARE_MARS_H

#include <stdint.h>

#define MARS_KEY_SIZE 16U
#define MARS_BLOCK_SIZE 16U

/* MARS-128: fixed 128-bit key profile of the IBM MARS block cipher. */
void mars_encrypt_block(uint8_t block[MARS_BLOCK_SIZE], const uint8_t key[MARS_KEY_SIZE]);
void mars_decrypt_block(uint8_t block[MARS_BLOCK_SIZE], const uint8_t key[MARS_KEY_SIZE]);

#endif
