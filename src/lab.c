/* author: cocomelonc */
#include "lab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MWA2 | algorithm (1) | IV length (1) | reserved (2) | IV slot (16). */
#define HEADER_SIZE 24
#define MAX_SAMPLE_SIZE (16UL * 1024UL * 1024UL)
#define SAMPLE_RESOURCE_BASE 101

static const char *sample_names[LAB_SAMPLE_COUNT] = {
  "Sample1.txt", "Sample2.txt", "Sample3.txt", "Sample4.txt", "Sample5.txt"
};

static void set_error(char *error, size_t capacity, const char *message) {
  if (error != NULL && capacity != 0) {
    snprintf(error, capacity, "%s", message);
  }
}

static bool join_path(char *out, size_t capacity, const char *left, const char *right) {
  int written = snprintf(out, capacity, "%s\\%s", left, right);
  return written >= 0 && (size_t)written < capacity;
}

static bool make_unique_lab_directory(char *out, size_t capacity) {
  char temp[MAX_PATH];
  DWORD temp_length = GetTempPathA(MAX_PATH, temp);
  unsigned int attempt;

  if (temp_length == 0 || temp_length >= MAX_PATH) {
    return false;
  }

  for (attempt = 0; attempt < 100; ++attempt) {
    int written = snprintf(out, capacity,
                 "%sMeowareLab-%lu-%lu-%u",
                 temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long)GetTickCount(),
                 attempt);
    if (written < 0 || (size_t)written >= capacity) {
      return false;
    }
    if (CreateDirectoryA(out, NULL)) {
      return true;
    }
    if (GetLastError() != ERROR_ALREADY_EXISTS) {
      return false;
    }
  }
  return false;
}

static bool read_file(const char *path, unsigned char **data, ULONG *size) {
  HANDLE file;
  LARGE_INTEGER file_size;
  DWORD read_size = 0;
  unsigned char *buffer;

  *data = NULL;
  *size = 0;
  file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
             FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
    file_size.QuadPart > MAX_SAMPLE_SIZE + HEADER_SIZE + CRYPTO_MAX_BLOCK_SIZE) {
    CloseHandle(file);
    return false;
  }
  buffer = (unsigned char *)HeapAlloc(GetProcessHeap(), 0,
                    file_size.QuadPart == 0 ? 1 : (SIZE_T)file_size.QuadPart);
  if (buffer == NULL) {
    CloseHandle(file);
    return false;
  }
  if (file_size.QuadPart != 0 &&
    (!ReadFile(file, buffer, (DWORD)file_size.QuadPart, &read_size, NULL) ||
     read_size != (DWORD)file_size.QuadPart)) {
    HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(file);
    return false;
  }
  CloseHandle(file);
  *data = buffer;
  *size = (ULONG)file_size.QuadPart;
  return true;
}

static bool write_new_file(const char *path, const unsigned char *data, ULONG size) {
  HANDLE file;
  DWORD written = 0;
  bool success;

  file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
             FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  success = size == 0 || (WriteFile(file, data, size, &written, NULL) && written == size);
  if (!CloseHandle(file)) {
    success = false;
  }
  if (!success) {
    DeleteFileA(path);
  }
  return success;
}

static bool create_sample_copies(const char *crypt_path, char *error, size_t error_capacity) {
  char destination[MAX_PATH];
  unsigned int i;

  for (i = 0; i < LAB_SAMPLE_COUNT; ++i) {
    HRSRC resource = FindResourceA(NULL,
                     MAKEINTRESOURCEA(SAMPLE_RESOURCE_BASE + i),
                     RT_RCDATA);
    HGLOBAL loaded;
    const void *data;
    DWORD size;

    if (resource == NULL) {
      snprintf(error, error_capacity,
           "Bundled sample %u is missing from this build.", i + 1);
      return false;
    }
    loaded = LoadResource(NULL, resource);
    data = loaded != NULL ? LockResource(loaded) : NULL;
    size = SizeofResource(NULL, resource);
    if (data == NULL || size == 0) {
      snprintf(error, error_capacity,
           "Bundled sample %u could not be loaded (Windows error %lu).",
           i + 1, (unsigned long)GetLastError());
      return false;
    }
    if (!join_path(destination, sizeof(destination), crypt_path, sample_names[i])) {
      snprintf(error, error_capacity, "The private sample path is too long.");
      return false;
    }
    if (!write_new_file(destination, (const unsigned char *)data, (ULONG)size)) {
      DWORD failure = GetLastError();
      snprintf(error, error_capacity,
           "Could not create sample %u in CryptPath (Windows error %lu).",
           i + 1, (unsigned long)failure);
      return false;
    }
  }
  return true;
}

bool lab_initialize(LabSession *lab, char *error, size_t error_capacity) {
  char crypt_path[MAX_PATH];
  char sample_error[256];

  if (lab == NULL) {
    set_error(error, error_capacity, "Invalid lab session.");
    return false;
  }
  memset(lab, 0, sizeof(*lab));

  if (!make_unique_lab_directory(lab->directory, sizeof(lab->directory)) ||
    !join_path(crypt_path, sizeof(crypt_path), lab->directory, "CryptPath") ||
    !CreateDirectoryA(crypt_path, NULL)) {
    set_error(error, error_capacity, "Could not create the private demo folder.");
    crypto_close(&lab->crypto);
    return false;
  }
  if (!create_sample_copies(crypt_path, sample_error, sizeof(sample_error))) {
    set_error(error, error_capacity, sample_error);
    crypto_close(&lab->crypto);
    return false;
  }
  snprintf(lab->directory, sizeof(lab->directory), "%s", crypt_path);
  lab->initialized = true;
  return true;
}

bool lab_encrypt_samples(LabSession *lab, CryptoAlgorithm selected, char *error, size_t error_capacity) {
  unsigned int i;
  const CryptoInfo *info = crypto_algorithm_info(selected);

  if (lab == NULL || !lab->initialized || lab->encrypted || lab->expired ||
      lab->restored || lab->crypto.initialized || info == NULL) {
    set_error(error, error_capacity, "The lab is not ready for encryption.");
    return false;
  }
  if (!crypto_init(&lab->crypto, selected)) {
    set_error(error, error_capacity, "Could not initialize the selected cipher and session key.");
    return false;
  }

  for (i = 0; i < LAB_SAMPLE_COUNT; ++i) {
    char input_path[MAX_PATH];
    char output_name[64];
    char output_path[MAX_PATH];
    unsigned char *plain = NULL;
    unsigned char *cipher = NULL;
    unsigned char *record = NULL;
    unsigned char iv[CRYPTO_MAX_BLOCK_SIZE] = { 0 };
    ULONG plain_size = 0;
    ULONG cipher_capacity;
    ULONG cipher_size = 0;
    bool success = false;

    if (!join_path(input_path, sizeof(input_path), lab->directory, sample_names[i]) ||
      !read_file(input_path, &plain, &plain_size) ||
      !crypto_random(iv, info->block_size)) {
      goto encrypt_failure;
    }
    if (plain_size > MAX_SAMPLE_SIZE) {
      goto encrypt_failure;
    }
    cipher_capacity = plain_size + info->block_size;
    cipher = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, cipher_capacity);
    if (cipher == NULL ||
      !crypto_encrypt(&lab->crypto, iv, plain, plain_size,
              cipher, cipher_capacity, &cipher_size)) {
      goto encrypt_failure;
    }

    record = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, HEADER_SIZE + cipher_size);
    if (record == NULL) {
      goto encrypt_failure;
    }
    memset(record, 0, HEADER_SIZE);
    memcpy(record, "MWA2", 4);
    record[4] = (unsigned char)selected;
    record[5] = (unsigned char)info->block_size;
    memcpy(record + 8, iv, info->block_size);
    memcpy(record + HEADER_SIZE, cipher, cipher_size);

    snprintf(output_name, sizeof(output_name), "%s.meoware", sample_names[i]);
    if (!join_path(output_path, sizeof(output_path), lab->directory, output_name) ||
      !write_new_file(output_path, record, HEADER_SIZE + cipher_size)) {
      goto encrypt_failure;
    }

    /* The source is a bundled demo copy created by this process. */
    if (!DeleteFileA(input_path)) {
      DeleteFileA(output_path);
      goto encrypt_failure;
    }
    success = true;

encrypt_failure:
    if (plain != NULL) {
      SecureZeroMemory(plain, plain_size);
      HeapFree(GetProcessHeap(), 0, plain);
    }
    if (cipher != NULL) HeapFree(GetProcessHeap(), 0, cipher);
    if (record != NULL) HeapFree(GetProcessHeap(), 0, record);
    SecureZeroMemory(iv, sizeof(iv));
    if (!success) {
      set_error(error, error_capacity, "Sample encryption failed in the demo folder.");
      return false;
    }
  }

  lab->encrypted = true;
  return true;
}

bool lab_restore_samples(LabSession *lab, char *error, size_t error_capacity) {
  unsigned int i;
  const CryptoInfo *info;

  if (lab == NULL || !lab->initialized || !lab->encrypted || lab->expired) {
    set_error(error, error_capacity, "There are no encrypted demo samples to restore.");
    return false;
  }
  info = crypto_algorithm_info(lab->crypto.selected);
  if (info == NULL || !lab->crypto.initialized) {
    set_error(error, error_capacity, "The session cipher is unavailable.");
    return false;
  }

  for (i = 0; i < LAB_SAMPLE_COUNT; ++i) {
    char input_name[64];
    char input_path[MAX_PATH];
    char output_path[MAX_PATH];
    unsigned char *record = NULL;
    unsigned char *plain = NULL;
    unsigned char *cipher;
    unsigned char iv[CRYPTO_MAX_BLOCK_SIZE] = { 0 };
    ULONG record_size = 0;
    ULONG plain_size = 0;
    ULONG cipher_size;
    bool success = false;

    snprintf(input_name, sizeof(input_name), "%s.meoware", sample_names[i]);
    if (!join_path(input_path, sizeof(input_path), lab->directory, input_name) ||
      !join_path(output_path, sizeof(output_path), lab->directory, sample_names[i]) ||
      !read_file(input_path, &record, &record_size) ||
      record_size <= HEADER_SIZE || memcmp(record, "MWA2", 4) != 0 ||
      record[4] != (unsigned char)info->id || record[5] != info->block_size ||
      record[6] != 0 || record[7] != 0 ||
      (record_size - HEADER_SIZE) % info->block_size != 0) {
      goto restore_failure;
    }
    cipher = record + HEADER_SIZE;
    cipher_size = record_size - HEADER_SIZE;
    memcpy(iv, record + 8, info->block_size);
    plain = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, cipher_size);
    if (plain == NULL ||
      !crypto_decrypt(&lab->crypto, iv, cipher, cipher_size,
              plain, cipher_size, &plain_size) ||
      !write_new_file(output_path, plain, plain_size)) {
      goto restore_failure;
    }
    if (!DeleteFileA(input_path)) {
      DeleteFileA(output_path);
      goto restore_failure;
    }
    success = true;

restore_failure:
    if (record != NULL) HeapFree(GetProcessHeap(), 0, record);
    if (plain != NULL) {
      SecureZeroMemory(plain, cipher_size);
      HeapFree(GetProcessHeap(), 0, plain);
    }
    SecureZeroMemory(iv, sizeof(iv));
    if (!success) {
      set_error(error, error_capacity, "Sample restoration failed; the lab data was left in place.");
      return false;
    }
  }

  lab->encrypted = false;
  lab->restored = true;
  return true;
}

bool lab_expire_samples(LabSession *lab, char *error, size_t error_capacity) {
  unsigned int i;

  if (lab == NULL || !lab->initialized || !lab->encrypted) {
    set_error(error, error_capacity, "The deadline scenario has no encrypted samples.");
    return false;
  }
  for (i = 0; i < LAB_SAMPLE_COUNT; ++i) {
    char name[64];
    char path[MAX_PATH];

    snprintf(name, sizeof(name), "%s.meoware", sample_names[i]);
    if (!join_path(path, sizeof(path), lab->directory, name) || !DeleteFileA(path)) {
      set_error(error, error_capacity, "Could not finish the deadline scenario.");
      return false;
    }
  }
  lab->encrypted = false;
  lab->expired = true;
  return true;
}

void lab_close(LabSession *lab) {
  if (lab != NULL) {
    crypto_close(&lab->crypto);
    lab->initialized = false;
  }
}

const char *lab_directory(const LabSession *lab) {
  return lab == NULL ? "" : lab->directory;
}
