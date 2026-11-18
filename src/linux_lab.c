/* author: cocomelonc */
#define _GNU_SOURCE
#include "linux_lab.h"
#include "crypto.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HEADER_SIZE 32U
#define BUFFER_SIZE (64U * 1024U)
#define MAX_FILES 100000U
#define MAX_DEPTH 64U
#define MAX_BYTES (256ULL * 1024ULL * 1024ULL)

typedef struct {
  char *path;
  struct stat original;
  struct stat record;
  unsigned char original_mac[CRYPTO_MAC_SIZE];
  bool staged;
  bool committed;
  bool removed;
} LinuxFile;

struct LinuxLab {
  char directory[PATH_MAX];
  int root;
  int state;
  CryptoContext crypto;
  unsigned char mac_key[CRYPTO_MAC_SIZE];
  LinuxFile *files;
  size_t count, allocated;
  uint64_t bytes;
};

static void fail(char *error, size_t capacity, const char *message) {
  if (error != NULL && capacity != 0) snprintf(error, capacity, "%s", message);
}

static void clear_files(LinuxLab *lab) {
  for (size_t i = 0; i < lab->count; ++i) {
    free(lab->files[i].path);
    SecureZeroMemory(&lab->files[i], sizeof(lab->files[i]));
  }
  free(lab->files);
  lab->files = NULL;
  lab->count = lab->allocated = 0;
  lab->bytes = 0;
}

/* Walk each relative parent through a directory descriptor; never follow links. */
static int parent_directory(LinuxLab *lab, const char *relative, char name[NAME_MAX + 1]) {
  char copy[PATH_MAX], *part, *next, *save = NULL;
  int current = openat(lab->root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (current < 0 || relative == NULL || relative[0] == '/' || strlen(relative) >= sizeof(copy)) {
    if (current >= 0) close(current);
    return -1;
  }
  snprintf(copy, sizeof(copy), "%s", relative);
  part = strtok_r(copy, "/", &save);
  while (part != NULL) {
    if (!strcmp(part, ".") || !strcmp(part, "..") || strlen(part) > NAME_MAX) break;
    next = strtok_r(NULL, "/", &save);
    if (next == NULL) {
      snprintf(name, NAME_MAX + 1, "%s", part);
      return current;
    }
    int child = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(current);
    if (child < 0) return -1;
    current = child;
    part = next;
  }
  close(current);
  return -1;
}

static bool suffix(char out[NAME_MAX + 1], const char *name, const char *extension) {
  int n = snprintf(out, NAME_MAX + 1, "%s%s", name, extension);
  return n >= 0 && n <= NAME_MAX;
}

static bool regular_owned(const struct stat *s) {
  return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1;
}

static bool same_file(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino && regular_owned(b);
}

static bool collect(LinuxLab *lab, int directory, const char *prefix, unsigned int depth,
                    char *error, size_t capacity) {
  int copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  DIR *stream = copy < 0 ? NULL : fdopendir(copy);
  if (stream == NULL) {
    if (copy >= 0) close(copy);
    fail(error, capacity, "Could not enumerate the private lab directory.");
    return false;
  }
  bool ok = true;
  for (;;) {
    errno = 0;
    struct dirent *item = readdir(stream);
    if (item == NULL) {
      if (errno != 0) ok = false;
      break;
    }
    if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
    char relative[PATH_MAX];
    int n = snprintf(relative, sizeof(relative), "%s%s%s", prefix, prefix[0] ? "/" : "", item->d_name);
    struct stat info;
    if (n < 0 || (size_t)n >= sizeof(relative) ||
        fstatat(directory, item->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0 || info.st_uid != geteuid()) {
      fail(error, capacity, "A corpus path is too long, inaccessible or not owned by this user.");
      ok = false;
      break;
    }
    if (S_ISDIR(info.st_mode)) {
      if (depth >= MAX_DEPTH) {
        fail(error, capacity, "The corpus exceeds the 64-directory depth limit.");
        ok = false;
        break;
      }
      int child = openat(directory, item->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (child < 0 || !collect(lab, child, relative, depth + 1, error, capacity)) ok = false;
      if (child >= 0) close(child);
      if (!ok) break;
    } else {
      if (!regular_owned(&info)) {
        fail(error, capacity, "Only owned regular files are accepted; symlinks, hard links and special files are rejected.");
        ok = false;
        break;
      }
      if (info.st_size < 0 || (uint64_t)info.st_size > MAX_BYTES - lab->bytes || lab->count >= MAX_FILES) {
        fail(error, capacity, "The lab limit is 256 MiB of payload and 100000 files per session.");
        ok = false;
        break;
      }
      if (lab->count == lab->allocated) {
        size_t count = lab->allocated ? lab->allocated * 2 : 32;
        LinuxFile *files = realloc(lab->files, count * sizeof(*files));
        if (files == NULL) {
          fail(error, capacity, "Could not allocate the session manifest.");
          ok = false;
          break;
        }
        lab->files = files;
        lab->allocated = count;
      }
      LinuxFile *file = &lab->files[lab->count];
      memset(file, 0, sizeof(*file));
      file->path = strdup(relative);
      if (file->path == NULL) { ok = false; break; }
      file->original = info;
      lab->bytes += (uint64_t)info.st_size;
      ++lab->count;
    }
  }
  closedir(stream);
  if (!ok && error != NULL && capacity && !error[0]) fail(error, capacity, "Corpus enumeration failed.");
  return ok;
}

static bool write_all(int fd, const unsigned char *buffer, size_t size) {
  while (size) {
    ssize_t n = write(fd, buffer, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    buffer += n;
    size -= (size_t)n;
  }
  return true;
}

static bool read_all(int fd, unsigned char *buffer, size_t size) {
  while (size) {
    ssize_t n = read(fd, buffer, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    buffer += n;
    size -= (size_t)n;
  }
  return true;
}

static uint64_t cipher_size(const CryptoInfo *info, uint64_t size) {
  return info->block_size ? (size / info->block_size + 1) * info->block_size : size;
}

static void header_write(unsigned char header[HEADER_SIZE], const CryptoInfo *info,
                         uint64_t size, const unsigned char iv[16]) {
  memset(header, 0, HEADER_SIZE);
  memcpy(header, "MWA3", 4);
  header[4] = (unsigned char)info->id;
  header[5] = (unsigned char)info->iv_size;
  for (unsigned int i = 0; i < 8; ++i) header[8 + i] = (unsigned char)(size >> (i * 8));
  memcpy(header + 16, iv, info->iv_size);
}

static bool original_matches(LinuxLab *lab, LinuxFile *file, int parent, const char *name) {
  int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  struct stat s;
  unsigned char buffer[BUFFER_SIZE], digest[CRYPTO_MAC_SIZE];
  CryptoMacContext mac = {0};
  bool ok = fd >= 0 && fstat(fd, &s) == 0 && regular_owned(&s) && s.st_size == file->original.st_size;
  if (ok && file->removed) ok = false;
  if (ok && !same_file(&file->original, &s)) ok = false;
  if (ok) ok = crypto_mac_init(&mac, lab->mac_key, sizeof(lab->mac_key));
  while (ok) {
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) { ok = false; break; }
    if (n == 0) break;
    ok = crypto_mac_update(&mac, buffer, (ULONG)n);
  }
  if (ok) ok = crypto_mac_final(&mac, digest) &&
                CRYPTO_memcmp(digest, file->original_mac, sizeof(digest)) == 0;
  if (fd >= 0) close(fd);
  crypto_mac_close(&mac);
  SecureZeroMemory(buffer, sizeof(buffer));
  SecureZeroMemory(digest, sizeof(digest));
  return ok;
}

static bool encrypt_stage(LinuxLab *lab, LinuxFile *file, const unsigned char iv[16]) {
  const CryptoInfo *info = crypto_algorithm_info(lab->crypto.selected);
  char name[NAME_MAX + 1], temporary[NAME_MAX + 1];
  int parent = parent_directory(lab, file->path, name), input = -1, output = -1;
  bool created = false, ok = false;
  unsigned char header[HEADER_SIZE], data[BUFFER_SIZE], result[BUFFER_SIZE + CRYPTO_MAX_BLOCK_SIZE];
  unsigned char tag[CRYPTO_MAC_SIZE];
  CryptoStream stream = {0};
  CryptoMacContext mac = {0}, original = {0};
  struct stat before, after;
  uint64_t consumed = 0, produced = 0;
  if (parent < 0 || !suffix(temporary, name, ".meoware.tmp")) goto done;
  input = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (input < 0 || fstat(input, &before) != 0 || !same_file(&file->original, &before) ||
      before.st_size != file->original.st_size) goto done;
  output = openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (output < 0) goto done;
  created = true;
  header_write(header, info, (uint64_t)before.st_size, iv);
  if (!crypto_stream_init(&stream, &lab->crypto, true, iv) ||
      !crypto_mac_init(&mac, lab->mac_key, sizeof(lab->mac_key)) ||
      !crypto_mac_init(&original, lab->mac_key, sizeof(lab->mac_key)) ||
      !crypto_mac_update(&mac, header, sizeof(header)) || !write_all(output, header, sizeof(header)))
    goto done;
  for (;;) {
    ssize_t n = read(input, data, sizeof(data));
    ULONG size = 0;
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) goto done;
    if (n == 0) break;
    consumed += (uint64_t)n;
    if (consumed > (uint64_t)before.st_size || !crypto_mac_update(&original, data, (ULONG)n) ||
        !crypto_stream_update(&stream, data, (ULONG)n, result, sizeof(result), &size) ||
        !crypto_mac_update(&mac, result, size) || !write_all(output, result, size)) goto done;
    produced += size;
  }
  ULONG size = 0;
  if (consumed != (uint64_t)before.st_size || fstat(input, &after) != 0 ||
      after.st_size != before.st_size || after.st_mtim.tv_sec != before.st_mtim.tv_sec ||
      after.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
      !crypto_stream_final(&stream, result, sizeof(result), &size) ||
      !crypto_mac_update(&mac, result, size) || !write_all(output, result, size)) goto done;
  produced += size;
  if (produced != cipher_size(info, consumed) || !crypto_mac_final(&mac, tag) ||
      !crypto_mac_final(&original, file->original_mac) || !write_all(output, tag, sizeof(tag)) ||
      fsync(output) != 0 || fstat(output, &file->record) != 0) goto done;
  if (close(output) != 0) { output = -1; goto done; }
  output = -1;
  file->staged = true;
  ok = true;
done:
  if (input >= 0) close(input);
  if (output >= 0) close(output);
  if (!ok && created) unlinkat(parent, temporary, 0);
  if (parent >= 0) close(parent);
  crypto_stream_close(&stream);
  crypto_mac_close(&mac);
  crypto_mac_close(&original);
  SecureZeroMemory(data, sizeof(data));
  SecureZeroMemory(result, sizeof(result));
  SecureZeroMemory(tag, sizeof(tag));
  return ok;
}

static void remove_staged(LinuxLab *lab) {
  for (size_t i = 0; i < lab->count; ++i) {
    if (!lab->files[i].staged) continue;
    char name[NAME_MAX + 1], temporary[NAME_MAX + 1];
    int parent = parent_directory(lab, lab->files[i].path, name);
    if (parent >= 0) {
      if (suffix(temporary, name, ".meoware.tmp")) unlinkat(parent, temporary, 0);
      close(parent);
    }
    lab->files[i].staged = false;
  }
}

LinuxLab *linux_lab_new(char *error, size_t capacity) {
  LinuxLab *lab = calloc(1, sizeof(*lab));
  if (error != NULL && capacity) error[0] = '\0';
  if (lab == NULL) { fail(error, capacity, "Could not allocate a lab session."); return NULL; }
  lab->root = -1;
  snprintf(lab->directory, sizeof(lab->directory), "/tmp/MeowareLab-%lu-XXXXXX", (unsigned long)geteuid());
  if (mkdtemp(lab->directory) == NULL ||
      (lab->root = open(lab->directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
    fail(error, capacity, "Could not create the private temporary lab directory.");
    if (lab->directory[0]) rmdir(lab->directory);
    free(lab);
    return NULL;
  }
  return lab;
}

void linux_lab_free(LinuxLab *lab) {
  if (lab == NULL) return;
  crypto_close(&lab->crypto);
  clear_files(lab);
  if (lab->root >= 0) close(lab->root);
  SecureZeroMemory(lab, sizeof(*lab));
  free(lab);
}

const char *linux_lab_directory(const LinuxLab *lab) { return lab ? lab->directory : ""; }
int linux_lab_state(const LinuxLab *lab) { return lab ? lab->state : -1; }
size_t linux_lab_file_count(const LinuxLab *lab) { return lab ? lab->count : 0; }
uint64_t linux_lab_bytes(const LinuxLab *lab) { return lab ? lab->bytes : 0; }

int linux_lab_encrypt(LinuxLab *lab, unsigned int algorithm, char *error, size_t capacity) {
  if (error != NULL && capacity) error[0] = '\0';
  if (lab == NULL || lab->state != 0 || lab->crypto.initialized ||
      crypto_algorithm_info((CryptoAlgorithm)algorithm) == NULL) {
    fail(error, capacity, "This session is not ready for encryption."); return 0;
  }
  clear_files(lab);
  if (!collect(lab, lab->root, "", 0, error, capacity)) goto failure;
  if (!lab->count) { fail(error, capacity, "Copy a disposable corpus into the private lab folder first."); goto failure; }
  for (size_t i = 0; i < lab->count; ++i) {
    char name[NAME_MAX + 1], record[NAME_MAX + 1], temporary[NAME_MAX + 1];
    struct stat s;
    int parent = parent_directory(lab, lab->files[i].path, name);
    bool ok = parent >= 0 && suffix(record, name, ".meoware") && suffix(temporary, name, ".meoware.tmp");
    if (ok) ok = fstatat(parent, record, &s, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    if (ok) ok = fstatat(parent, temporary, &s, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    if (parent >= 0) close(parent);
    if (!ok) { fail(error, capacity, "An output already exists or a file name is too long."); goto failure; }
  }
  if (!crypto_init(&lab->crypto, (CryptoAlgorithm)algorithm) ||
      !crypto_random(lab->mac_key, sizeof(lab->mac_key))) {
    fail(error, capacity, "Could not initialize the cipher and authentication key."); goto failure;
  }
  uint32_t frame = 0;
  if (algorithm == CRYPTO_A51 && !crypto_random((unsigned char *)&frame, sizeof(frame))) goto failure;
  frame &= A51_FRAME_MASK;
  const CryptoInfo *info = crypto_algorithm_info((CryptoAlgorithm)algorithm);
  for (size_t i = 0; i < lab->count; ++i) {
    unsigned char iv[16] = {0};
    if (algorithm == CRYPTO_A51) {
      uint32_t count = (frame + (uint32_t)i) & A51_FRAME_MASK;
      for (unsigned int j = 0; j < 3; ++j) iv[j] = (unsigned char)(count >> (8 * j));
    } else if (!crypto_random(iv, info->iv_size)) goto failure;
    if (!encrypt_stage(lab, &lab->files[i], iv)) {
      fail(error, capacity, "Could not stage a complete authenticated record; originals remain."); goto failure;
    }
  }
  for (size_t i = 0; i < lab->count; ++i) {
    LinuxFile *file = &lab->files[i];
    char name[NAME_MAX + 1], record[NAME_MAX + 1], temporary[NAME_MAX + 1];
    int parent = parent_directory(lab, file->path, name);
    bool ok = parent >= 0 && suffix(record, name, ".meoware") && suffix(temporary, name, ".meoware.tmp") &&
              renameat2(parent, temporary, parent, record, RENAME_NOREPLACE) == 0;
    if (ok) { file->staged = false; file->committed = true; lab->state = 1; ok = fsync(parent) == 0; }
    if (parent >= 0) close(parent);
    if (!ok) { fail(error, capacity, "Record commit was interrupted; originals remain and local restore is available."); goto failure; }
  }
  for (size_t i = 0; i < lab->count; ++i) {
    LinuxFile *file = &lab->files[i];
    char name[NAME_MAX + 1];
    int parent = parent_directory(lab, file->path, name);
    struct stat s;
    bool ok = parent >= 0 && original_matches(lab, file, parent, name) &&
              fstatat(parent, name, &s, AT_SYMLINK_NOFOLLOW) == 0 && same_file(&file->original, &s) &&
              unlinkat(parent, name, 0) == 0;
    if (ok) { file->removed = true; ok = fsync(parent) == 0; }
    if (parent >= 0) close(parent);
    if (!ok) { fail(error, capacity, "A source changed or could not be removed. Use Restore lab."); return 0; }
  }
  return 1;
failure:
  remove_staged(lab);
  if (lab->state == 0) {
    crypto_close(&lab->crypto);
    SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
    clear_files(lab);
  }
  return 0;
}

static bool restore_record(LinuxLab *lab, LinuxFile *file, bool write_plain) {
  const CryptoInfo *info = crypto_algorithm_info(lab->crypto.selected);
  char name[NAME_MAX + 1], record[NAME_MAX + 1], temporary[NAME_MAX + 1];
  int parent = parent_directory(lab, file->path, name), input = -1, output = -1;
  bool created = false, ok = false;
  struct stat s;
  unsigned char header[HEADER_SIZE], expected[HEADER_SIZE], data[BUFFER_SIZE];
  unsigned char result[BUFFER_SIZE + CRYPTO_MAX_BLOCK_SIZE], tag[CRYPTO_MAC_SIZE], digest[CRYPTO_MAC_SIZE];
  unsigned char plain_tag[CRYPTO_MAC_SIZE];
  CryptoStream stream = {0};
  CryptoMacContext mac = {0}, original = {0};
  uint64_t remaining = cipher_size(info, (uint64_t)file->original.st_size), produced = 0;
  if (parent < 0 || !suffix(record, name, ".meoware") || !suffix(temporary, name, ".restore.tmp")) goto done;
  input = openat(parent, record, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (input < 0 || fstat(input, &s) != 0 || !same_file(&file->record, &s) ||
      s.st_size < 0 || (uint64_t)s.st_size != HEADER_SIZE + remaining + CRYPTO_MAC_SIZE ||
      !read_all(input, header, sizeof(header))) goto done;
  header_write(expected, info, (uint64_t)file->original.st_size, header + 16);
  if (memcmp(header, expected, sizeof(header)) != 0 ||
      !crypto_stream_init(&stream, &lab->crypto, false, header + 16) ||
      !crypto_mac_init(&mac, lab->mac_key, sizeof(lab->mac_key)) ||
      !crypto_mac_init(&original, lab->mac_key, sizeof(lab->mac_key)) ||
      !crypto_mac_update(&mac, header, sizeof(header))) goto done;
  if (write_plain) {
    if (fstatat(parent, name, &s, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) goto done;
    output = openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) goto done;
    created = true;
  }
  while (remaining) {
    ULONG amount = remaining > BUFFER_SIZE ? BUFFER_SIZE : (ULONG)remaining, size = 0;
    if (!read_all(input, data, amount) || !crypto_mac_update(&mac, data, amount) ||
        !crypto_stream_update(&stream, data, amount, result, sizeof(result), &size) ||
        !crypto_mac_update(&original, result, size) ||
        (write_plain && !write_all(output, result, size))) goto done;
    remaining -= amount;
    produced += size;
  }
  ULONG size = 0;
  if (!crypto_stream_final(&stream, result, sizeof(result), &size) ||
      !crypto_mac_update(&original, result, size) || (write_plain && !write_all(output, result, size))) goto done;
  produced += size;
  if (produced != (uint64_t)file->original.st_size || !read_all(input, tag, sizeof(tag)) ||
      !crypto_mac_final(&mac, digest) || !crypto_mac_final(&original, plain_tag) ||
      CRYPTO_memcmp(tag, digest, sizeof(tag)) != 0 ||
      CRYPTO_memcmp(plain_tag, file->original_mac, sizeof(plain_tag)) != 0) goto done;
  if (write_plain) {
    struct timespec times[] = {file->original.st_atim, file->original.st_mtim};
    if (fchmod(output, file->original.st_mode & 0777) != 0 || futimens(output, times) != 0 || fsync(output) != 0)
      goto done;
    if (close(output) != 0) { output = -1; goto done; }
    output = -1;
    if (renameat2(parent, temporary, parent, name, RENAME_NOREPLACE) != 0) goto done;
    created = false;
    /* Track the recovered inode so interrupted record removal can be retried. */
    if (fstatat(parent, name, &file->original, AT_SYMLINK_NOFOLLOW) != 0) goto done;
    file->removed = false;
    if (fsync(parent) != 0) goto done;
  }
  ok = true;
done:
  if (input >= 0) close(input);
  if (output >= 0) close(output);
  if (created) unlinkat(parent, temporary, 0);
  if (parent >= 0) close(parent);
  crypto_stream_close(&stream);
  crypto_mac_close(&mac);
  crypto_mac_close(&original);
  SecureZeroMemory(data, sizeof(data));
  SecureZeroMemory(result, sizeof(result));
  SecureZeroMemory(tag, sizeof(tag));
  SecureZeroMemory(digest, sizeof(digest));
  SecureZeroMemory(plain_tag, sizeof(plain_tag));
  return ok;
}

int linux_lab_restore(LinuxLab *lab, char *error, size_t capacity) {
  if (error != NULL && capacity) error[0] = '\0';
  if (lab == NULL || lab->state != 1 || !lab->crypto.initialized) {
    fail(error, capacity, "There is no active encrypted session to restore."); return 0;
  }
  /* Verify every committed record before committing any recovered plaintext. */
  for (size_t i = 0; i < lab->count; ++i) {
    LinuxFile *file = &lab->files[i];
    if (!file->committed) continue;
    char name[NAME_MAX + 1];
    int parent = parent_directory(lab, file->path, name);
    bool ok = parent >= 0 && (file->removed || original_matches(lab, file, parent, name));
    if (parent >= 0) close(parent);
    if (!ok || !restore_record(lab, file, false)) {
      fail(error, capacity, "Record authentication, original identity or length check failed; no new files were restored.");
      return 0;
    }
  }
  for (size_t i = 0; i < lab->count; ++i) {
    LinuxFile *file = &lab->files[i];
    if (!file->committed) continue;
    if (!restore_record(lab, file, file->removed)) {
      fail(error, capacity, "Restore was interrupted. Keep this session open and retry."); return 0;
    }
    char name[NAME_MAX + 1], record[NAME_MAX + 1];
    struct stat s;
    int parent = parent_directory(lab, file->path, name);
    bool ok = parent >= 0 && suffix(record, name, ".meoware") &&
              fstatat(parent, record, &s, AT_SYMLINK_NOFOLLOW) == 0 && same_file(&file->record, &s) &&
              unlinkat(parent, record, 0) == 0;
    if (ok) { file->committed = false; ok = fsync(parent) == 0; }
    if (parent >= 0) close(parent);
    if (!ok) { fail(error, capacity, "Plaintext is recovered, but a record could not be removed. Retry local restore."); return 0; }
  }
  lab->state = 2;
  crypto_close(&lab->crypto);
  SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
  return 1;
}

int linux_lab_expire(LinuxLab *lab, char *error, size_t capacity) {
  if (error != NULL && capacity) error[0] = '\0';
  if (lab == NULL || lab->state != 1) { fail(error, capacity, "There is no encrypted deadline session."); return 0; }
  for (size_t i = 0; i < lab->count; ++i) {
    LinuxFile *file = &lab->files[i];
    if (!file->committed) continue;
    char name[NAME_MAX + 1], record[NAME_MAX + 1];
    struct stat s;
    int parent = parent_directory(lab, file->path, name);
    bool ok = parent >= 0 && suffix(record, name, ".meoware") &&
              fstatat(parent, record, &s, AT_SYMLINK_NOFOLLOW) == 0 && same_file(&file->record, &s) &&
              unlinkat(parent, record, 0) == 0;
    if (ok) {
      file->committed = false;
      lab->state = 3;
      ok = fsync(parent) == 0;
    }
    if (parent >= 0) close(parent);
    if (!ok) {
      if (lab->state == 3) {
        crypto_close(&lab->crypto);
        SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
        fail(error, capacity, "The deadline partially completed. Some session records could not be removed.");
      } else {
        fail(error, capacity, "The deadline could not remove any records. Local restore remains available.");
      }
      return 0;
    }
  }
  lab->state = 3;
  crypto_close(&lab->crypto);
  SecureZeroMemory(lab->mac_key, sizeof(lab->mac_key));
  return 1;
}
