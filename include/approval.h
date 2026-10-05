#ifndef MEOWARE_APPROVAL_H
#define MEOWARE_APPROVAL_H

#include "json.h"

bool approval_matches(Json callback, int64_t chat_id, int64_t message_id, const char *reference,
                      char query_id[128]);

#endif
