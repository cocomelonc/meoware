/* author: cocomelonc */
#include "lab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MWA3 | algorithm | IV length | reserved | plaintext size | IV | ciphertext | HMAC-SHA-256. */
#define MWA_HEADER_SIZE 32U
#define MWA_TAG_SIZE CRYPTO_MAC_SIZE
#define IO_BUFFER_SIZE (64U * 1024U)
#define MAX_LAB_FILES 100000U
#define MAX_LAB_DEPTH 64U
#define LAB_MARKER "MeowareLab-"

struct LabFileEntry {
  char *relative_path;
  ULONGLONG original_size;
  DWORD attributes;
  FILETIME creation_time;
  FILETIME access_time;
  FILETIME write_time;
  unsigned char original_mac[CRYPTO_MAC_SIZE];
  bool source_removed;
};

static void set_error(char *error, size_t capacity, const char *message) {
  if (error != NULL && capacity != 0) snprintf(error, capacity, "%s", message);
}

static bool join_path(char *out, size_t capacity, const char *left, const char *right) {
  int written = snprintf(out, capacity, "%s\\%s", left, right);
  return written >= 0 && (size_t)written < capacity;
}

static bool append_suffix(char *out, size_t capacity, const char *path, const char *suffix) {
  int written = snprintf(out, capacity, "%s%s", path, suffix);
  return written >= 0 && (size_t)written < capacity;
}

static bool make_unique_lab_directory(char *out, size_t capacity) {
  char temp[MAX_PATH];
  DWORD temp_length = GetTempPathA(MAX_PATH, temp);
  unsigned int attempt;

  if (temp_length == 0 || temp_length >= MAX_PATH) return false;
  for (attempt = 0; attempt < 100; ++attempt) {
    int written = snprintf(out, capacity, "%s%s%lu-%lu-%u", temp, LAB_MARKER,
                           (unsigned long)GetCurrentProcessId(),
                           (unsigned long)GetTickCount(), attempt);
    if (written < 0 || (size_t)written >= capacity) return false;
    if (CreateDirectoryA(out, NULL)) return true;
    if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
  }
  return false;
}

static void free_file_list(LabSession *lab) {
  size_t index;
  if (lab == NULL) return;
  for (index = 0; index < lab->file_count; ++index) {
    free(lab->files[index].relative_path);
    SecureZeroMemory(&lab->files[index], sizeof(lab->files[index]));
  }
  free(lab->files);
  lab->files = NULL;
  lab->file_count = 0;
  lab->file_capacity = 0;
}

static bool append_file(LabSession *lab, const char *relative_path,
                        const WIN32_FIND_DATAA *data, char *error, size_t error_capacity) {
  LabFileEntry *grown;
  LabFileEntry *entry;
  size_t capacity;
  size_t length;

  if (lab->file_count >= MAX_LAB_FILES) {
    set_error(error, error_capacity, "The lab corpus exceeds the 100000-file safety limit.");
    return false;
  }
  if (lab->file_count == lab->file_capacity) {
    capacity = lab->file_capacity == 0 ? 32 : lab->file_capacity * 2;
    if (capacity > MAX_LAB_FILES) capacity = MAX_LAB_FILES;
    grown = (LabFileEntry *)realloc(lab->files, capacity * sizeof(*lab->files));
    if (grown == NULL) {
      set_error(error, error_capacity, "Could not allocate the lab file manifest.");
      return false;
    }
    lab->files = grown;
    lab->file_capacity = capacity;
  }
  length = strlen(relative_path);
  entry = &lab->files[lab->file_count];
  memset(entry, 0, sizeof(*entry));
  entry->relative_path = (char *)malloc(length + 1);
  if (entry->relative_path == NULL) {
    set_error(error, error_capacity, "Could not allocate a lab path entry.");
    return false;
  }
  memcpy(entry->relative_path, relative_path, length + 1);
  entry->original_size = ((ULONGLONG)data->nFileSizeHigh << 32) | data->nFileSizeLow;
  entry->attributes = data->dwFileAttributes;
  entry->creation_time = data->ftCreationTime;
  entry->access_time = data->ftLastAccessTime;
  entry->write_time = data->ftLastWriteTime;
  ++lab->file_count;
  return true;
}

static bool collect_directory(LabSession *lab, const char *relative_directory, unsigned int depth,
                              char *error, size_t error_capacity) {
  char directory[MAX_PATH];
  char pattern[MAX_PATH];
  WIN32_FIND_DATAA item;
  HANDLE find;
  bool success = true;

  if (depth > MAX_LAB_DEPTH) {
    set_error(error, error_capacity, "The lab corpus exceeds the 64-directory depth limit.");
    return false;
  }
  if (relative_directory[0] == '\0') {
    snprintf(directory, sizeof(directory), "%s", lab->directory);
  } else if (!join_path(directory, sizeof(directory), lab->directory, relative_directory)) {
    set_error(error, error_capacity, "A lab path is too long for this Windows build.");
    return false;
  }
  if (!join_path(pattern, sizeof(pattern), directory, "*")) {
    set_error(error, error_capacity, "A lab directory path is too long.");
    return false;
  }
  find = FindFirstFileA(pattern, &item);
  if (find == INVALID_HANDLE_VALUE) {
    set_error(error, error_capacity, "Could not enumerate a lab directory.");
    return false;
  }

  do {
    char relative_path[MAX_PATH];
    if (strcmp(item.cFileName, ".") == 0 || strcmp(item.cFileName, "..") == 0) continue;
    if ((item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
      set_error(error, error_capacity,
                "The lab corpus contains a symbolic link or junction; remove it before running.");
      success = false;
      break;
    }
    if (relative_directory[0] == '\0') {
      int written = snprintf(relative_path, sizeof(relative_path), "%s", item.cFileName);
      if (written < 0 || (size_t)written >= sizeof(relative_path)) {
        set_error(error, error_capacity, "A lab file name is too long.");
        success = false;
        break;
      }
    } else {
      if (!join_path(relative_path, sizeof(relative_path), relative_directory, item.cFileName)) {
        set_error(error, error_capacity, "A nested lab path is too long.");
        success = false;
        break;
      }
    }

    if ((item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      if (!collect_directory(lab, relative_path, depth + 1, error, error_capacity)) {
        success = false;
        break;
      }
    } else {
      if ((item.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) != 0) {
        set_error(error, error_capacity, "The lab corpus contains an unsupported device entry.");
        success = false;
        break;
      }
      if (!append_file(lab, relative_path, &item, error, error_capacity)) {
        success = false;
        break;
      }
    }
  } while (FindNextFileA(find, &item));

  if (success && GetLastError() != ERROR_NO_MORE_FILES) {
    set_error(error, error_capacity, "Lab directory enumeration failed.");
    success = false;
  }
  FindClose(find);
  return success;
}

static bool build_file_paths(const LabSession *lab, const LabFileEntry *entry, char *source,
                             size_t source_capacity, char *encrypted, size_t encrypted_capacity,
                             char *temporary, size_t temporary_capacity) {
  if (!join_path(source, source_capacity, lab->directory, entry->relative_path) ||
      !append_suffix(encrypted, encrypted_capacity, source, ".meoware") ||
      !append_suffix(temporary, temporary_capacity, encrypted, ".tmp"))
    return false;
  return true;
}

static void write_u64le(unsigned char out[8], ULONGLONG value) {
  unsigned int index;
  for (index = 0; index < 8; ++index) out[index] = (unsigned char)(value >> (index * 8));
}

static ULONGLONG read_u64le(const unsigned char in[8]) {
  ULONGLONG value = 0;
  unsigned int index;
  for (index = 0; index < 8; ++index) value |= (ULONGLONG)in[index] << (index * 8);
  return value;
}

static bool cipher_size_for_plain(const CryptoInfo *info, ULONGLONG plain_size,
                                  ULONGLONG *cipher_size) {
  ULONGLONG blocks;
  if (info == NULL || cipher_size == NULL) return false;
  if (info->block_size == 0) {
    *cipher_size = plain_size;
    return true;
  }
  blocks = plain_size / info->block_size + 1;
  if (blocks > (~(ULONGLONG)0) / info->block_size) return false;
  *cipher_size = blocks * info->block_size;
  return true;
}

static bool write_exact(HANDLE file, const unsigned char *data, ULONG size) {
  ULONG offset = 0;
  while (offset < size) {
    DWORD written = 0;
    DWORD request = size - offset;
    if (!WriteFile(file, data + offset, request, &written, NULL) || written == 0) return false;
    offset += written;
  }
  return true;
}

static bool read_exact(HANDLE file, unsigned char *data, ULONG size) {
  ULONG offset = 0;
  while (offset < size) {
    DWORD read_size = 0;
    DWORD request = size - offset;
    if (!ReadFile(file, data + offset, request, &read_size, NULL) || read_size == 0) return false;
    offset += read_size;
  }
  return true;
}

static bool secure_equal(const unsigned char *left, const unsigned char *right, size_t length) {
  volatile unsigned char difference = 0;
  size_t index;
  for (index = 0; index < length; ++index) difference |= left[index] ^ right[index];
  return difference == 0;
}

static bool file_matches_original(LabSession *lab, const LabFileEntry *entry, const char *path,
                                  char *error, size_t error_capacity) {
  HANDLE file = INVALID_HANDLE_VALUE;
  LARGE_INTEGER size;
  unsigned char buffer[IO_BUFFER_SIZE];
  unsigned char digest[CRYPTO_MAC_SIZE];
  ULONGLONG remaining;
  CryptoMacContext mac;
  bool mac_ready = false;
  bool matches = false;

  memset(&mac, 0, sizeof(mac));
  memset(digest, 0, sizeof(digest));
  file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
      (ULONGLONG)size.QuadPart != entry->original_size ||
      !crypto_mac_init(&mac, lab->mac_key, sizeof(lab->mac_key))) {
    set_error(error, error_capacity,
              "A lab source changed while encrypted; the recovery record was preserved.");
    goto cleanup;
  }
  mac_ready = true;
  remaining = entry->original_size;
  while (remaining != 0) {
    DWORD request = remaining > sizeof(buffer) ? (DWORD)sizeof(buffer) : (DWORD)remaining;
    if (!read_exact(file, buffer, request) || !crypto_mac_update(&mac, buffer, request)) {
      set_error(error, error_capacity, "Could not verify a lab source against its original bytes.");
      goto cleanup;
    }
    remaining -= request;
  }
  if (!crypto_mac_final(&mac, digest) ||
      !secure_equal(entry->original_mac, digest, sizeof(digest))) {
    set_error(error, error_capacity,
              "A lab source differs from its original bytes; the recovery record was preserved.");
    goto cleanup;
  }
  matches = true;

cleanup:
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  if (mac_ready) crypto_mac_close(&mac);
  SecureZeroMemory(buffer, sizeof(buffer));
  SecureZeroMemory(digest, sizeof(digest));
  return matches;
}

static bool make_header(unsigned char header[MWA_HEADER_SIZE], const CryptoInfo *info,
                        ULONGLONG plain_size, const unsigned char iv[CRYPTO_MAX_BLOCK_SIZE]) {
  if (header == NULL || info == NULL || iv == NULL || info->iv_size > CRYPTO_MAX_BLOCK_SIZE)
    return false;
  memset(header, 0, MWA_HEADER_SIZE);
  memcpy(header, "MWA3", 4);
  header[4] = (unsigned char)info->id;
  header[5] = (unsigned char)info->iv_size;
  write_u64le(header + 8, plain_size);
  memcpy(header + 16, iv, info->iv_size);
  return true;
}

static bool validate_header(const unsigned char header[MWA_HEADER_SIZE],
                            const CryptoInfo *expected, ULONGLONG expected_plain_size,
                            unsigned char iv[CRYPTO_MAX_BLOCK_SIZE],
                            ULONGLONG *cipher_size) {
  const CryptoInfo *info;
  unsigned int index;
  ULONGLONG plain_size;
  if (memcmp(header, "MWA3", 4) != 0 || header[6] != 0 || header[7] != 0) return false;
  info = crypto_algorithm_info((CryptoAlgorithm)header[4]);
  if (info == NULL || expected == NULL || info->id != expected->id ||
      header[5] != info->iv_size || info->iv_size > CRYPTO_MAX_BLOCK_SIZE)
    return false;
  for (index = info->iv_size; index < CRYPTO_MAX_BLOCK_SIZE; ++index) {
    if (header[16 + index] != 0) return false;
  }
  plain_size = read_u64le(header + 8);
  if (plain_size != expected_plain_size || !cipher_size_for_plain(info, plain_size, cipher_size))
    return false;
  memset(iv, 0, CRYPTO_MAX_BLOCK_SIZE);
  memcpy(iv, header + 16, info->iv_size);
  if (info->id == CRYPTO_A51 && (iv[2] & 0xc0) != 0) return false;
  return true;
}

static bool encrypt_file_to_temporary(LabSession *lab, LabFileEntry *entry,
                                      const CryptoInfo *info, const unsigned char iv[16],
                                      char *error, size_t error_capacity) {
  char source_path[MAX_PATH], encrypted_path[MAX_PATH], temporary_path[MAX_PATH];
  HANDLE source = INVALID_HANDLE_VALUE, output = INVALID_HANDLE_VALUE;
  LARGE_INTEGER file_size;
  unsigned char header[MWA_HEADER_SIZE];
  unsigned char input[IO_BUFFER_SIZE];
  unsigned char transformed[IO_BUFFER_SIZE + CRYPTO_MAX_BLOCK_SIZE];
  unsigned char tag[CRYPTO_MAC_SIZE];
  CryptoStream stream;
  CryptoMacContext mac;
  CryptoMacContext plain_mac;
  ULONGLONG remaining;
  bool stream_ready = false, mac_ready = false, success = false;

  memset(&stream, 0, sizeof(stream));
  memset(&mac, 0, sizeof(mac));
  memset(&plain_mac, 0, sizeof(plain_mac));
  if (!build_file_paths(lab, entry, source_path, sizeof(source_path), encrypted_path,
                        sizeof(encrypted_path), temporary_path, sizeof(temporary_path))) {
    set_error(error, error_capacity, "A lab file path is too long for an output record.");
    return false;
  }
  source = CreateFileA(source_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (source == INVALID_HANDLE_VALUE || !GetFileSizeEx(source, &file_size) || file_size.QuadPart < 0 ||
      (ULONGLONG)file_size.QuadPart != entry->original_size) {
    set_error(error, error_capacity, "A lab file changed or could not be opened for reading.");
    goto cleanup;
  }
  output = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                       NULL);
  if (output == INVALID_HANDLE_VALUE) {
    set_error(error, error_capacity, "Could not create a temporary encrypted lab record.");
    goto cleanup;
  }
  if (!make_header(header, info, entry->original_size, iv) ||
      !crypto_stream_init(&stream, &lab->crypto, true, iv)) {
    set_error(error, error_capacity, "Could not initialize streaming encryption.");
    goto cleanup;
  }
  stream_ready = true;
  if (!crypto_mac_init(&mac, lab->mac_key, sizeof(lab->mac_key))) {
    set_error(error, error_capacity, "Could not initialize record authentication.");
    goto cleanup;
  }
  mac_ready = true;
  if (!crypto_mac_init(&plain_mac, lab->mac_key, sizeof(lab->mac_key))) {
    set_error(error, error_capacity, "Could not initialize source integrity tracking.");
    goto cleanup;
  }
  if (!crypto_mac_update(&mac, header, sizeof(header)) || !write_exact(output, header, sizeof(header))) {
    set_error(error, error_capacity, "Could not write the encrypted record header.");
    goto cleanup;
  }

  remaining = entry->original_size;
  while (remaining != 0) {
    DWORD request = remaining > sizeof(input) ? (DWORD)sizeof(input) : (DWORD)remaining;
    DWORD got = 0;
    ULONG transformed_size = 0;
    if (!ReadFile(source, input, request, &got, NULL) || got == 0 || got > request ||
        !crypto_stream_update(&stream, input, got, transformed, sizeof(transformed),
                              &transformed_size) ||
        !crypto_mac_update(&plain_mac, input, got) ||
        !crypto_mac_update(&mac, transformed, transformed_size) ||
        !write_exact(output, transformed, transformed_size)) {
      set_error(error, error_capacity, "Streaming encryption failed while reading a lab file.");
      goto cleanup;
    }
    remaining -= got;
  }
  {
    ULONG transformed_size = 0;
    if (!crypto_stream_final(&stream, transformed, sizeof(transformed), &transformed_size) ||
        !crypto_mac_update(&mac, transformed, transformed_size) ||
        !write_exact(output, transformed, transformed_size) ||
        !crypto_mac_final(&mac, tag) ||
        !crypto_mac_final(&plain_mac, entry->original_mac) ||
        !write_exact(output, tag, sizeof(tag)) ||
        !FlushFileBuffers(output)) {
      set_error(error, error_capacity, "Could not finalize an encrypted lab record.");
      goto cleanup;
    }
  }
  success = true;

cleanup:
  if (source != INVALID_HANDLE_VALUE) CloseHandle(source);
  if (output != INVALID_HANDLE_VALUE && !CloseHandle(output)) {
    success = false;
    set_error(error, error_capacity, "Could not close a temporary encrypted lab record.");
  }
  if (stream_ready) crypto_stream_close(&stream);
  if (mac_ready) crypto_mac_close(&mac);
  crypto_mac_close(&plain_mac);
  SecureZeroMemory(input, sizeof(input));
  SecureZeroMemory(transformed, sizeof(transformed));
  SecureZeroMemory(tag, sizeof(tag));
  SecureZeroMemory(header, sizeof(header));
  if (!success && temporary_path[0] != '\0') DeleteFileA(temporary_path);
  return success;
}

static bool encrypt_entry_iv(const CryptoInfo *info, size_t index, uint32_t frame_base,
                             unsigned char iv[CRYPTO_MAX_BLOCK_SIZE]) {
  memset(iv, 0, CRYPTO_MAX_BLOCK_SIZE);
  if (info->id == CRYPTO_A51) {
    uint32_t frame = (frame_base + (uint32_t)index) & A51_FRAME_MASK;
    for (unsigned int byte = 0; byte < A51_IV_SIZE; ++byte)
      iv[byte] = (unsigned char)(frame >> (8 * byte));
    return true;
  }
  return crypto_random(iv, info->iv_size);
}

static void remove_uncommitted_temporaries(LabSession *lab) {
  size_t index;
  for (index = 0; index < lab->file_count; ++index) {
    char source[MAX_PATH], encrypted[MAX_PATH], temporary[MAX_PATH];
    if (build_file_paths(lab, &lab->files[index], source, sizeof(source), encrypted,
                         sizeof(encrypted), temporary, sizeof(temporary)))
      DeleteFileA(temporary);
  }
}

bool lab_initialize(LabSession *lab, char *error, size_t error_capacity) {
  char crypt_path[MAX_PATH];
  if (lab == NULL) {
    set_error(error, error_capacity, "Invalid lab session.");
    return false;
  }
  memset(lab, 0, sizeof(*lab));
  if (!make_unique_lab_directory(lab->directory, sizeof(lab->directory)) ||
      !join_path(crypt_path, sizeof(crypt_path), lab->directory, "CryptPath") ||
      !CreateDirectoryA(crypt_path, NULL)) {
    set_error(error, error_capacity, "Could not create the private demo folder.");
    return false;
  }
  snprintf(lab->directory, sizeof(lab->directory), "%s", crypt_path);
  lab->initialized = true;
  return true;
}

bool lab_encrypt_tree(LabSession *lab, CryptoAlgorithm selected, char *error,
                      size_t error_capacity) {
  const CryptoInfo *info = crypto_algorithm_info(selected);
  uint32_t frame_base = 0;
  size_t index;
  bool any_committed = false;

  if (error != NULL && error_capacity != 0) error[0] = '\0';
  if (lab == NULL || !lab->initialized || lab->encrypted || lab->expired || lab->restored ||
      lab->crypto.initialized || info == NULL) {
    set_error(error, error_capacity, "The lab is not ready for encryption.");
    return false;
  }
  free_file_list(lab);
  if (!collect_directory(lab, "", 0, error, error_capacity)) {
    free_file_list(lab);
    return false;
  }
  if (lab->file_count == 0) {
    set_error(error, error_capacity,
              "The private lab folder is empty. Copy disposable corpus files into it first.");
    free_file_list(lab);
    return false;
  }
  if (selected == CRYPTO_A51 && lab->file_count > (size_t)A51_FRAME_MASK + 1) {
    set_error(error, error_capacity, "The A5/1 lab profile supports at most 4194304 files per run.");
    free_file_list(lab);
    return false;
  }
  if (!crypto_init(&lab->crypto, selected) || !crypto_random(lab->mac_key, sizeof(lab->mac_key)) ||
      (selected == CRYPTO_A51 &&
       !crypto_random((unsigned char *)&frame_base, sizeof(frame_base)))) {
    crypto_close(&lab->crypto);
    SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
    set_error(error, error_capacity, "Could not initialize the session cipher and MAC key.");
    free_file_list(lab);
    return false;
  }
  frame_base &= A51_FRAME_MASK;

  /* Preflight every output before writing any encrypted data. */
  for (index = 0; index < lab->file_count; ++index) {
    char source[MAX_PATH], encrypted[MAX_PATH], temporary[MAX_PATH];
    if (!build_file_paths(lab, &lab->files[index], source, sizeof(source), encrypted,
                          sizeof(encrypted), temporary, sizeof(temporary)) ||
        GetFileAttributesA(encrypted) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(temporary) != INVALID_FILE_ATTRIBUTES) {
      set_error(error, error_capacity,
                "An encrypted output already exists or a corpus path is too long.");
      goto failure_before_commit;
    }
  }

  /* First write and flush every ciphertext record while all originals still exist. */
  for (index = 0; index < lab->file_count; ++index) {
    unsigned char iv[CRYPTO_MAX_BLOCK_SIZE];
    bool success = encrypt_entry_iv(info, index, frame_base, iv) &&
                   encrypt_file_to_temporary(lab, &lab->files[index], info, iv, error,
                                             error_capacity);
    SecureZeroMemory(iv, sizeof(iv));
    if (!success) {
      if (error != NULL && error_capacity != 0 && error[0] == '\0')
        set_error(error, error_capacity, "A lab file could not be encrypted.");
      remove_uncommitted_temporaries(lab);
      goto failure_before_commit;
    }
  }

  /* Commit sidecars only after all staged files are complete. */
  for (index = 0; index < lab->file_count; ++index) {
    char source[MAX_PATH], encrypted[MAX_PATH], temporary[MAX_PATH];
    if (!build_file_paths(lab, &lab->files[index], source, sizeof(source), encrypted,
                          sizeof(encrypted), temporary, sizeof(temporary)) ||
        !MoveFileExA(temporary, encrypted, MOVEFILE_WRITE_THROUGH)) {
      remove_uncommitted_temporaries(lab);
      set_error(error, error_capacity,
                "Could not commit every encrypted record; originals remain and restore is available.");
      if (any_committed) {
        lab->encrypted = true;
      } else {
        crypto_close(&lab->crypto);
        SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
        free_file_list(lab);
      }
      return false;
    }
    any_committed = true;
    lab->encrypted = true;
  }

  /* Keep recovery possible if removing any original fails. */
  for (index = 0; index < lab->file_count; ++index) {
    char source[MAX_PATH], encrypted[MAX_PATH], temporary[MAX_PATH];
    if (!build_file_paths(lab, &lab->files[index], source, sizeof(source), encrypted,
                          sizeof(encrypted), temporary, sizeof(temporary))) {
      set_error(error, error_capacity, "A lab path changed during encryption; restore is available.");
      return false;
    }
    if (!file_matches_original(lab, &lab->files[index], source, error, error_capacity)) return false;
    if (!DeleteFileA(source)) {
      set_error(error, error_capacity,
                "Encryption is partial; use Restore now. A source file could not be removed.");
      return false;
    }
    lab->files[index].source_removed = true;
  }
  return true;

failure_before_commit:
  if (!lab->encrypted) {
    crypto_close(&lab->crypto);
    SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
    free_file_list(lab);
  }
  return false;
}

static bool decrypt_or_verify_entry(LabSession *lab, LabFileEntry *entry, bool write_plain,
                                    char *error, size_t error_capacity) {
  char source_path[MAX_PATH], encrypted_path[MAX_PATH], temporary_path[MAX_PATH];
  HANDLE input = INVALID_HANDLE_VALUE, output = INVALID_HANDLE_VALUE;
  LARGE_INTEGER file_size;
  unsigned char header[MWA_HEADER_SIZE];
  unsigned char input_buffer[IO_BUFFER_SIZE];
  unsigned char output_buffer[IO_BUFFER_SIZE + CRYPTO_MAX_BLOCK_SIZE];
  unsigned char stored_tag[CRYPTO_MAC_SIZE], calculated_tag[CRYPTO_MAC_SIZE];
  unsigned char plaintext_tag[CRYPTO_MAC_SIZE];
  unsigned char iv[CRYPTO_MAX_BLOCK_SIZE];
  CryptoStream stream;
  CryptoMacContext mac;
  CryptoMacContext plain_mac;
  const CryptoInfo *info;
  ULONGLONG cipher_size, expected_record_size, remaining, plaintext_written = 0;
  bool stream_ready = false, mac_ready = false, success = false, created_temporary = false;

  memset(&stream, 0, sizeof(stream));
  memset(&mac, 0, sizeof(mac));
  memset(&plain_mac, 0, sizeof(plain_mac));
  memset(iv, 0, sizeof(iv));
  if (!build_file_paths(lab, entry, source_path, sizeof(source_path), encrypted_path,
                        sizeof(encrypted_path), temporary_path, sizeof(temporary_path)) ||
      !append_suffix(temporary_path, sizeof(temporary_path), source_path, ".restore.tmp")) {
    set_error(error, error_capacity, "A lab restore path is too long.");
    return false;
  }
  info = crypto_algorithm_info(lab->crypto.selected);
  input = CreateFileA(encrypted_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (input == INVALID_HANDLE_VALUE || !GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0 ||
      !read_exact(input, header, sizeof(header)) ||
      !validate_header(header, info, entry->original_size, iv, &cipher_size) ||
      cipher_size > (~(ULONGLONG)0) - MWA_HEADER_SIZE - MWA_TAG_SIZE) {
    set_error(error, error_capacity, "An encrypted lab record is missing or invalid.");
    goto cleanup;
  }
  expected_record_size = MWA_HEADER_SIZE + cipher_size + MWA_TAG_SIZE;
  if ((ULONGLONG)file_size.QuadPart != expected_record_size) {
    set_error(error, error_capacity, "An encrypted lab record has an invalid length.");
    goto cleanup;
  }
  if (write_plain) {
    output = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (output == INVALID_HANDLE_VALUE) {
      set_error(error, error_capacity, "Could not create a temporary restored lab file.");
      goto cleanup;
    }
    created_temporary = true;
  }
  if (!crypto_mac_init(&mac, lab->mac_key, sizeof(lab->mac_key))) {
    set_error(error, error_capacity, "Could not verify the encrypted record.");
    goto cleanup;
  }
  mac_ready = true;
  if (!crypto_mac_init(&plain_mac, lab->mac_key, sizeof(lab->mac_key)) ||
      !crypto_mac_update(&mac, header, sizeof(header)) ||
      !crypto_stream_init(&stream, &lab->crypto, false, iv)) {
    set_error(error, error_capacity, "Could not initialize streaming restoration.");
    goto cleanup;
  }
  stream_ready = true;

  remaining = cipher_size;
  while (remaining != 0) {
    DWORD request = remaining > sizeof(input_buffer) ? (DWORD)sizeof(input_buffer)
                                                      : (DWORD)remaining;
    ULONG output_size = 0;
    if (!read_exact(input, input_buffer, request) ||
        !crypto_mac_update(&mac, input_buffer, request) ||
        !crypto_stream_update(&stream, input_buffer, request, output_buffer,
                              sizeof(output_buffer), &output_size) ||
        !crypto_mac_update(&plain_mac, output_buffer, output_size) ||
        (write_plain && !write_exact(output, output_buffer, output_size))) {
      set_error(error, error_capacity, "Streaming restoration failed for a lab record.");
      goto cleanup;
    }
    plaintext_written += output_size;
    remaining -= request;
  }
  {
    ULONG output_size = 0;
    if (!crypto_stream_final(&stream, output_buffer, sizeof(output_buffer), &output_size) ||
        !crypto_mac_update(&plain_mac, output_buffer, output_size) ||
        (write_plain && !write_exact(output, output_buffer, output_size))) {
      set_error(error, error_capacity, "The encrypted lab record has invalid padding.");
      goto cleanup;
    }
    plaintext_written += output_size;
  }
  if (plaintext_written != entry->original_size || !read_exact(input, stored_tag, sizeof(stored_tag)) ||
      !crypto_mac_final(&mac, calculated_tag) ||
      !crypto_mac_final(&plain_mac, plaintext_tag) ||
      !secure_equal(stored_tag, calculated_tag, sizeof(stored_tag)) ||
      !secure_equal(entry->original_mac, plaintext_tag, sizeof(plaintext_tag))) {
    set_error(error, error_capacity, "Encrypted record authentication failed; no file was restored.");
    goto cleanup;
  }
  if (write_plain) {
    if (!SetFileTime(output, &entry->creation_time, &entry->access_time, &entry->write_time) ||
        !FlushFileBuffers(output) || !CloseHandle(output)) {
      output = INVALID_HANDLE_VALUE;
      set_error(error, error_capacity, "Could not flush the restored lab file.");
      goto cleanup;
    }
    output = INVALID_HANDLE_VALUE;
    if (!MoveFileExA(temporary_path, source_path, MOVEFILE_WRITE_THROUGH) ||
        !SetFileAttributesA(source_path, entry->attributes & ~(FILE_ATTRIBUTE_DIRECTORY |
                                                               FILE_ATTRIBUTE_REPARSE_POINT))) {
      set_error(error, error_capacity, "Could not commit the restored lab file.");
      goto cleanup;
    }
    created_temporary = false;
  }
  success = true;

cleanup:
  if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
  if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
  if (stream_ready) crypto_stream_close(&stream);
  if (mac_ready) crypto_mac_close(&mac);
  crypto_mac_close(&plain_mac);
  SecureZeroMemory(input_buffer, sizeof(input_buffer));
  SecureZeroMemory(output_buffer, sizeof(output_buffer));
  SecureZeroMemory(stored_tag, sizeof(stored_tag));
  SecureZeroMemory(calculated_tag, sizeof(calculated_tag));
  SecureZeroMemory(plaintext_tag, sizeof(plaintext_tag));
  SecureZeroMemory(header, sizeof(header));
  SecureZeroMemory(iv, sizeof(iv));
  if (!success && created_temporary) DeleteFileA(temporary_path);
  return success;
}

bool lab_restore_tree(LabSession *lab, char *error, size_t error_capacity) {
  size_t index;
  if (lab == NULL || !lab->initialized || !lab->encrypted || lab->expired ||
      !lab->crypto.initialized || lab->file_count == 0) {
    set_error(error, error_capacity, "There are no encrypted lab files to restore.");
    return false;
  }
  for (index = 0; index < lab->file_count; ++index) {
    LabFileEntry *entry = &lab->files[index];
    char source[MAX_PATH], encrypted[MAX_PATH], temporary[MAX_PATH];
    DWORD source_attributes, encrypted_attributes;
    bool source_exists, encrypted_exists;
    if (!build_file_paths(lab, entry, source, sizeof(source), encrypted, sizeof(encrypted),
                          temporary, sizeof(temporary))) {
      set_error(error, error_capacity, "A lab restore path is too long.");
      return false;
    }
    source_attributes = GetFileAttributesA(source);
    encrypted_attributes = GetFileAttributesA(encrypted);
    source_exists = source_attributes != INVALID_FILE_ATTRIBUTES;
    encrypted_exists = encrypted_attributes != INVALID_FILE_ATTRIBUTES;
    if (source_exists && !encrypted_exists && !entry->source_removed) {
      entry->source_removed = false;
      continue; /* This entry was already restored during an earlier attempt. */
    }
    if (source_exists && !encrypted_exists) {
      set_error(error, error_capacity, "An encrypted record is missing for a removed lab source.");
      return false;
    }
    if (!encrypted_exists) {
      set_error(error, error_capacity, "A lab source and its recovery record are both missing.");
      return false;
    }
    if (source_exists && !file_matches_original(lab, entry, source, error, error_capacity))
      return false;
    if (!decrypt_or_verify_entry(lab, entry, !source_exists, error, error_capacity)) return false;
    if (!DeleteFileA(encrypted)) {
      set_error(error, error_capacity, "A restored lab file is safe, but its record could not be removed.");
      return false;
    }
    entry->source_removed = false;
  }
  lab->encrypted = false;
  lab->restored = true;
  crypto_close(&lab->crypto);
  SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
  return true;
}

bool lab_expire_tree(LabSession *lab, char *error, size_t error_capacity) {
  size_t index;
  if (lab == NULL || !lab->initialized || !lab->encrypted || lab->file_count == 0) {
    set_error(error, error_capacity, "The deadline scenario has no encrypted lab files.");
    return false;
  }
  for (index = 0; index < lab->file_count; ++index) {
    char source[MAX_PATH], encrypted[MAX_PATH], temporary[MAX_PATH];
    if (!build_file_paths(lab, &lab->files[index], source, sizeof(source), encrypted,
                          sizeof(encrypted), temporary, sizeof(temporary)) ||
        (GetFileAttributesA(encrypted) != INVALID_FILE_ATTRIBUTES && !DeleteFileA(encrypted))) {
      set_error(error, error_capacity, "Could not finish the deadline scenario.");
      return false;
    }
  }
  lab->encrypted = false;
  lab->expired = true;
  crypto_close(&lab->crypto);
  SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
  return true;
}

void lab_close(LabSession *lab) {
  if (lab == NULL) return;
  crypto_close(&lab->crypto);
  SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
  free_file_list(lab);
  lab->initialized = false;
}

const char *lab_directory(const LabSession *lab) {
  return lab == NULL ? "" : lab->directory;
}
