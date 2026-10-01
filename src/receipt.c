/* author: cocomelonc */
#include "receipt.h"

void receipt_open(DemoReceipt *receipt) {
  *receipt = (DemoReceipt){ .phase = RECEIPT_WAITING };
}

bool receipt_submit(DemoReceipt *receipt, uint64_t now) {
  if (receipt->phase != RECEIPT_WAITING) return false;
  receipt->submitted_at = now;
  receipt->credited_units = RECEIPT_DEMO_UNITS;
  receipt->phase = RECEIPT_PENDING;
  return true;
}

bool receipt_advance(DemoReceipt *receipt, uint64_t now) {
  uint64_t completed;
  if (receipt->phase != RECEIPT_PENDING || now < receipt->submitted_at) return false;
  completed = (now - receipt->submitted_at) / RECEIPT_STEP_MS;
  if (completed > RECEIPT_STEPS) completed = RECEIPT_STEPS;
  if (completed <= receipt->confirmations) return false;
  receipt->confirmations = (unsigned int)completed;
  if (completed == RECEIPT_STEPS) receipt->phase = RECEIPT_CONFIRMED;
  return true;
}

void receipt_close(DemoReceipt *receipt) {
  receipt->phase = RECEIPT_CLOSED;
}
