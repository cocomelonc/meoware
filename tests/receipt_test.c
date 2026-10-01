/* author: cocomelonc */
#include <assert.h>
#include <stdio.h>
#include "receipt.h"

int main(void) {
  DemoReceipt receipt = { 0 };
  assert(!receipt_submit(&receipt, 100));
  assert(!receipt_advance(&receipt, UINT64_MAX));
  receipt_open(&receipt);
  assert(!receipt_advance(&receipt, UINT64_MAX));
  assert(receipt_submit(&receipt, 100));
  assert(receipt.credited_units == RECEIPT_DEMO_UNITS);
  assert(!receipt_submit(&receipt, 200));
  assert(!receipt_advance(&receipt, 99));
  assert(!receipt_advance(&receipt, 2099));
  assert(receipt_advance(&receipt, 2100));
  assert(receipt.confirmations == 1);
  assert(!receipt_advance(&receipt, 2100));
  assert(!receipt_advance(&receipt, 100));
  assert(receipt_advance(&receipt, 4100));
  assert(receipt.confirmations == 2 && receipt.phase == RECEIPT_PENDING);
  assert(receipt_advance(&receipt, 6100));
  assert(receipt.confirmations == 3 && receipt.phase == RECEIPT_CONFIRMED);
  assert(!receipt_submit(&receipt, 6200));
  receipt_close(&receipt);
  assert(!receipt_advance(&receipt, UINT64_MAX));
  assert(!receipt_submit(&receipt, 6300));

  /* Restore, expiry, or errors cancel an unfinished mock transfer. */
  receipt_open(&receipt);
  assert(receipt.confirmations == 0);
  assert(receipt.credited_units == 0);
  assert(receipt_submit(&receipt, 0));
  receipt_close(&receipt);
  assert(!receipt_advance(&receipt, 6000));
  assert(receipt.phase == RECEIPT_CLOSED && receipt.confirmations == 0);
  assert(receipt.credited_units == RECEIPT_DEMO_UNITS);

  /* A delayed UI tick completes the receipt without overflowing. */
  receipt_open(&receipt);
  assert(receipt_submit(&receipt, 0));
  assert(receipt_advance(&receipt, UINT64_MAX));
  assert(receipt.confirmations == RECEIPT_STEPS);
  assert(receipt.phase == RECEIPT_CONFIRMED);
  puts("Receipt tests passed.");
  return 0;
}
