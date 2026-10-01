#ifndef MEOWARE_RECEIPT_H
#define MEOWARE_RECEIPT_H

#include <stdbool.h>
#include <stdint.h>

#define RECEIPT_DEMO_UNITS 25U
#define RECEIPT_STEPS 3U
#define RECEIPT_STEP_MS 2000U

typedef enum {
  RECEIPT_INACTIVE,
  RECEIPT_WAITING,
  RECEIPT_PENDING,
  RECEIPT_CONFIRMED,
  RECEIPT_CLOSED
} ReceiptPhase;

/* In-memory teaching model: no wallet, network, or real monetary value. */
typedef struct {
  ReceiptPhase phase;
  uint64_t submitted_at;
  unsigned int credited_units;
  unsigned int confirmations;
} DemoReceipt;

void receipt_open(DemoReceipt *receipt);
bool receipt_submit(DemoReceipt *receipt, uint64_t now);
bool receipt_advance(DemoReceipt *receipt, uint64_t now);
void receipt_close(DemoReceipt *receipt);

#endif
