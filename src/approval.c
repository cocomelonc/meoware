/* author: cocomelonc */
#include "approval.h"
#include <stdio.h>
#include <string.h>

bool approval_matches(Json callback, int64_t chat_id, int64_t message_id,
                      const char *reference, char query_id[128]) {
  Json message = json_get(callback, "message");
  int64_t sender, chat, id;
  char data[64], expected[64], type[16];
  snprintf(expected, sizeof(expected), "meow:%s", reference);
  if (!json_integer(json_get(json_get(callback, "from"), "id"), &sender) || sender != chat_id ||
      !json_integer(json_get(json_get(message, "chat"), "id"), &chat) || chat != chat_id ||
      !json_string(json_get(json_get(message, "chat"), "type"), type, sizeof(type)) || strcmp(type, "private") ||
      !json_integer(json_get(message, "message_id"), &id) || id != message_id ||
      !json_string(json_get(callback, "data"), data, sizeof(data)) || strcmp(data, expected) ||
      !json_string(json_get(callback, "id"), query_id, 128) || !query_id[0]) return false;
  for (const char *p = query_id; *p; ++p) {
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') ||
          (*p >= 'A' && *p <= 'Z') || *p == '_' || *p == '-')) return false;
  }
  return true;
}
