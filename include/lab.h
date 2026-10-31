#ifndef MEOWARE_LAB_H
#define MEOWARE_LAB_H

#include <stdbool.h>
#include <windows.h>
#include "crypto.h"

typedef struct LabFileEntry LabFileEntry;

typedef struct {
  char directory[MAX_PATH];
  CryptoContext crypto;
  unsigned char mac_key[CRYPTO_MAC_SIZE];
  LabFileEntry *files;
  size_t file_count;
  size_t file_capacity;
  bool initialized;
  bool encrypted;
  bool restored;
  bool expired;
} LabSession;

bool lab_initialize(LabSession *lab, char *error, size_t error_capacity);
bool lab_encrypt_tree(LabSession *lab, CryptoAlgorithm selected, char *error,
                      size_t error_capacity);
bool lab_restore_tree(LabSession *lab, char *error, size_t error_capacity);
bool lab_expire_tree(LabSession *lab, char *error, size_t error_capacity);
void lab_close(LabSession *lab);
const char *lab_directory(const LabSession *lab);

#endif
