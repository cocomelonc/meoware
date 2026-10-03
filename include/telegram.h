#ifndef MEOWARE_TELEGRAM_H
#define MEOWARE_TELEGRAM_H

#include <stdbool.h>
#include <windows.h>

#define WM_TELEGRAM (WM_APP + 3)
enum { TELEGRAM_IDLE, TELEGRAM_WAITING, TELEGRAM_APPROVED, TELEGRAM_FAILED, TELEGRAM_SENDING };
/* Only a fictional receipt reference crosses the network. */
bool telegram_start(HWND window, char reference[33]);
void telegram_cancel(void);
const char *telegram_error(unsigned long code);

#endif
