/* author: cocomelonc */
#include "approval.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *reference = "0123456789abcdef0123456789abcdef";

static void approval_case(int sender, int chat, int message, const char *data, bool expected) {
  char input[512], query[128];
  snprintf(input, sizeof(input), "{\"id\":\"12345\",\"from\":{\"id\":%d},"
    "\"message\":{\"message_id\":%d,\"chat\":{\"id\":%d,\"type\":\"private\"}},\"data\":\"%s\"}", sender, message, chat, data);
  Json value;
  assert(json_parse(input, strlen(input), &value));
  assert(approval_matches(value, 42, 77, reference, query) == expected);
  if (expected) assert(!strcmp(query, "12345"));
}

int main(void) {
  const char *data = "meow:0123456789abcdef0123456789abcdef";
  approval_case(42, 42, 77, data, true);
  approval_case(99, 42, 77, data, false);
  approval_case(42, 99, 77, data, false);
  approval_case(42, 42, 76, data, false);
  approval_case(42, 42, 77, "meow:old-session", false);
  approval_case(42, 42, 77, "payment", false);

  Json document;
  char text[128];
  int64_t number;
  const char *sample = " {\"ok\":true,\"result\":[{\"update_id\":100,\"text\":\"ignore } ] \\\"\"},"
                       "{\"update_id\":101}],\"empty\":[],\"escaped\":\"a\\/b\"} ";
  assert(json_parse(sample, strlen(sample), &document));
  assert(json_true(json_get(document, "ok")));
  assert(json_integer(json_get(json_at(json_get(document, "result"), 1), "update_id"), &number) && number == 101);
  assert(!json_at(json_get(document, "result"), 2).size);
  assert(!json_at(json_get(document, "empty"), 0).size);
  assert(!json_get(document, "missing").size);
  assert(json_string(json_get(document, "escaped"), text, sizeof(text)) && !strcmp(text, "a/b"));
  assert(!json_string(json_get(document, "escaped"), text, 2));
  assert(!json_integer(json_get(document, "ok"), &number));

  const char *invalid[] = { "", " ", "{", "[1,]", "{\"a\":}", "{\"a\" 1}",
    "[true false]", "01", "-", "1.", "1e", "true false", "\"\\x\"", "\"\\u12x4\"", "\"unterminated", "\"line\n\"" };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    assert(!json_parse(invalid[i], strlen(invalid[i]), &document));
  assert(!json_parse("true\0", 5, &document));
  const char *valid[] = { "null", "false", "{}", "[]", "-0", "1.2e-3", "\"\\u1234\"" };
  for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    assert(json_parse(valid[i], strlen(valid[i]), &document));

  const char *integers[] = { "9223372036854775807", "-9223372036854775808", "9223372036854775808", "-9223372036854775809", "0" };
  for (size_t i = 0; i < 5; ++i) {
    assert(json_parse(integers[i], strlen(integers[i]), &document));
    assert(json_integer(document, &number) == (i < 2 || i == 4));
    if (i == 0) assert(number == INT64_MAX);
    if (i == 1) assert(number == INT64_MIN);
  }
  char deep[160];
  memset(deep, '[', 70); memset(deep + 70, ']', 70);
  assert(!json_parse(deep, 140, &document));

  /* Truncation and random network data must never read past the buffer. */
  for (size_t length = 0; length < strlen(sample) - 1; ++length)
    assert(!json_parse(sample, length, &document));
  uint32_t state = 1;
  for (size_t run = 0; run < 5000; ++run) {
    for (size_t i = 0; i < sizeof(deep); ++i) {
      state = state * UINT32_C(1664525) + UINT32_C(1013904223);
      deep[i] = (char)(state >> 24);
    }
    json_parse(deep, run % sizeof(deep), &document);
  }
  puts("Telegram approval identity, session, message binding, and JSON bounds passed.");
  return 0;
}
