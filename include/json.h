#ifndef MEOWARE_JSON_H
#define MEOWARE_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct { const char *text; size_t size; } Json;
bool json_parse(const char *text, size_t size, Json *value);
Json json_get(Json object, const char *key);
Json json_at(Json array, size_t index);
bool json_string(Json value, char *output, size_t capacity);
bool json_integer(Json value, int64_t *number);
bool json_true(Json value);

#endif
