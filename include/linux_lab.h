#ifndef MEOWARE_LINUX_LAB_H
#define MEOWARE_LINUX_LAB_H

#include <stddef.h>
#include <stdint.h>

typedef struct LinuxLab LinuxLab;

/* The only target is the private directory created by linux_lab_new(). */
LinuxLab *linux_lab_new(char *error, size_t capacity);
void linux_lab_free(LinuxLab *lab);
const char *linux_lab_directory(const LinuxLab *lab);
int linux_lab_state(const LinuxLab *lab); /* 0 ready, 1 encrypted, 2 restored, 3 expired. */
size_t linux_lab_file_count(const LinuxLab *lab);
uint64_t linux_lab_bytes(const LinuxLab *lab);
int linux_lab_encrypt(LinuxLab *lab, unsigned int algorithm, char *error, size_t capacity);
int linux_lab_restore(LinuxLab *lab, char *error, size_t capacity);
int linux_lab_expire(LinuxLab *lab, char *error, size_t capacity);

#endif
