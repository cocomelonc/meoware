#ifndef MEOWARE_LAB_H
#define MEOWARE_LAB_H

#include <stdbool.h>
#include <windows.h>
#include "crypto.h"

#define LAB_SAMPLE_COUNT 5

typedef struct {
    char directory[MAX_PATH];
    CryptoContext crypto;
    bool initialized;
    bool encrypted;
    bool restored;
    bool expired;
} LabSession;

bool lab_initialize(LabSession *lab, char *error, size_t error_capacity);
bool lab_encrypt_samples(LabSession *lab, CryptoAlgorithm selected, char *error, size_t error_capacity);
bool lab_restore_samples(LabSession *lab, char *error, size_t error_capacity);
bool lab_expire_samples(LabSession *lab, char *error, size_t error_capacity);
void lab_close(LabSession *lab);
const char *lab_directory(const LabSession *lab);

#endif
