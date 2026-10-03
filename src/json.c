/* author: cocomelonc */
#include "json.h"
#include <string.h>

static void space(const char **cursor, const char *end) {
  while (*cursor < end && **cursor && strchr(" \t\r\n", **cursor) != NULL) ++*cursor;
}

static bool string(const char **cursor, const char *end) {
  if (*cursor == end || *(*cursor)++ != '"') return false;
  while (*cursor < end) {
    unsigned char c = (unsigned char)*(*cursor)++;
    if (c == '"') return true;
    if (c < 32) return false;
    if (c == '\\') {
      if (*cursor == end) return false;
      c = (unsigned char)*(*cursor)++;
      if (c == 'u') {
        for (int i = 0; i < 4; ++i) {
          if (*cursor == end || **cursor == 0 || !strchr("0123456789abcdefABCDEF", *(*cursor)++)) return false;
        }
      } else if (c == 0 || !strchr("\"\\/bfnrt", c)) return false;
    }
  }
  return false;
}

static bool digit(char c) { return c >= '0' && c <= '9'; }

static bool value(const char **cursor, const char *end, unsigned int depth) {
  const char *p = *cursor;
  if (p == end || depth > 32) return false;
  if (*p == '"') return string(cursor, end);
  if (*p == '{' || *p == '[') {
    bool object = *p++ == '{';
    char close = object ? '}' : ']';
    space(&p, end);
    if (p < end && *p == close) { *cursor = p + 1; return true; }
    while (p < end) {
      if (object) {
        if (!string(&p, end)) return false;
        space(&p, end);
        if (p == end || *p++ != ':') return false;
        space(&p, end);
      }
      if (!value(&p, end, depth + 1)) return false;
      space(&p, end);
      if (p == end) return false;
      if (*p == close) { *cursor = p + 1; return true; }
      if (*p++ != ',') return false;
      space(&p, end);
    }
    return false;
  }
  const char *words[] = { "true", "false", "null" };
  for (size_t i = 0; i < 3; ++i) {
    size_t length = strlen(words[i]);
    if ((size_t)(end - p) >= length && !memcmp(p, words[i], length)) {
      *cursor = p + length; return true;
    }
  }
  if (*p == '-') ++p;
  if (p == end || !digit(*p)) return false;
  if (*p++ != '0') while (p < end && digit(*p)) ++p;
  if (p < end && *p == '.') {
    if (++p == end || !digit(*p)) return false;
    while (p < end && digit(*p)) ++p;
  }
  if (p < end && (*p == 'e' || *p == 'E')) {
    ++p;
    if (p < end && (*p == '+' || *p == '-')) ++p;
    if (p == end || !digit(*p)) return false;
    while (p < end && digit(*p)) ++p;
  }
  *cursor = p;
  return true;
}

bool json_parse(const char *text, size_t size, Json *output) {
  const char *p = text, *end = text + size, *start;
  *output = (Json){ 0 };
  space(&p, end); start = p;
  if (!value(&p, end, 0)) return false;
  Json parsed = { start, (size_t)(p - start) };
  space(&p, end);
  if (p != end) return false;
  *output = parsed;
  return true;
}

/* Accessors operate only on values returned from a successful parse. */
static Json child(Json parent, const char *key, size_t index) {
  if (!parent.size || parent.text[0] != (key ? '{' : '[')) return (Json){ 0 };
  const char *p = parent.text + 1, *end = parent.text + parent.size - 1;
  for (size_t i = 0; p < end; ++i) {
    bool match = i == index;
    space(&p, end);
    if (p == end) break;
    if (key) {
      const char *start = p;
      if (!string(&p, end)) break;
      match = (size_t)(p - start) == strlen(key) + 2 && !memcmp(start + 1, key, strlen(key));
      space(&p, end); ++p; space(&p, end);
    }
    const char *start = p;
    if (!value(&p, end, 0)) break;
    if (match) return (Json){ start, (size_t)(p - start) };
    space(&p, end);
    if (p < end) ++p;
  }
  return (Json){ 0 };
}

Json json_get(Json object, const char *key) { return child(object, key, 0); }
Json json_at(Json array, size_t index) { return child(array, NULL, index); }

bool json_string(Json input, char *output, size_t capacity) {
  if (input.size < 2 || input.text[0] != '"' || !capacity) return false;
  size_t used = 0;
  for (size_t i = 1; i < input.size - 1; ++i) {
    char c = input.text[i];
    if (c == '\\') {
      c = input.text[++i];
      if (c != '"' && c != '\\' && c != '/') return false;
    }
    if (used + 1 >= capacity) return false;
    output[used++] = c;
  }
  output[used] = 0;
  return true;
}

bool json_integer(Json input, int64_t *number) {
  uint64_t result = 0;
  bool negative = input.size && input.text[0] == '-';
  uint64_t limit = (uint64_t)INT64_MAX + negative;
  if (input.size <= (size_t)negative) return false;
  for (size_t i = negative; i < input.size; ++i) {
    if (!digit(input.text[i])) return false;
    unsigned int n = (unsigned int)(input.text[i] - '0');
    if (result > (limit - n) / 10) return false;
    result = result * 10 + n;
  }
  *number = negative ? -(int64_t)(result - (result != 0)) - (result != 0) : (int64_t)result;
  return true;
}

bool json_true(Json input) { return input.size == 4 && !memcmp(input.text, "true", 4); }
