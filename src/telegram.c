/* author: cocomelonc */
#define WIN32_LEAN_AND_MEAN
#include "telegram.h"
#include "approval.h"
#include "crypto.h"
#include "resource.h"
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define RESPONSE_CAPACITY (256U * 1024U)

typedef struct {
  HWND window;
  HANDLE stop;
  HINTERNET session, connection;
  char token[128], reference[33];
  int64_t chat_id;
  char response[RESPONSE_CAPACITY];
} Telegram;

static HANDLE worker, stop_event;

static const void *resource(WORD id, DWORD *size) {
  HMODULE module = GetModuleHandleA(NULL);
  HRSRC found = FindResourceA(module, MAKEINTRESOURCEA(id), RT_RCDATA);
  if (!found) return NULL;
  *size = SizeofResource(module, found);
  return LockResource(LoadResource(module, found));
}

static unsigned long request(Telegram *bot, const char *method, const wchar_t *content_type,
                             void *body, DWORD length, Json *result) {
  wchar_t path[256];
  DWORD status = 0, size = sizeof(status), used = 0, received;
  unsigned long error = 0;
  swprintf(path, 256, L"/bot%hs/%hs", bot->token, method);
  HINTERNET call = WinHttpOpenRequest(bot->connection, L"POST", path, NULL,
    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!call) return GetLastError();
  DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  if (!WinHttpSetOption(call, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)) ||
      !WinHttpSendRequest(call, content_type, (DWORD)-1, body, length, length, 0) ||
      !WinHttpReceiveResponse(call, NULL) ||
      !WinHttpQueryHeaders(call, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
    error = GetLastError(); goto done;
  }
  if (status != 200) { error = status; goto done; }
  do {
    if (used == sizeof(bot->response) - 1) { error = ERROR_BUFFER_OVERFLOW; goto done; }
    if (!WinHttpReadData(call, bot->response + used, sizeof(bot->response) - 1 - used, &received)) {
      error = GetLastError(); goto done;
    }
    used += received;
  } while (received);
  bot->response[used] = 0;
  Json document;
  if (!json_parse(bot->response, used, &document) || !json_true(json_get(document, "ok"))) {
    error = ERROR_INVALID_DATA; goto done;
  }
  *result = json_get(document, "result");
done:
  WinHttpCloseHandle(call);
  return error;
}

static unsigned long call_json(Telegram *bot, const char *method, char *body, Json *result) {
  return request(bot, method, L"Content-Type: application/json\r\n", body, (DWORD)strlen(body), result);
}

static bool configure(Telegram *bot) {
  DWORD size = 0;
  const char *data = resource(IDR_TELEGRAM_CONFIG, &size);
  Json config;
  if (!data || !json_parse(data, size, &config) ||
      !json_string(json_get(config, "token"), bot->token, sizeof(bot->token)) ||
      !json_integer(json_get(config, "chat_id"), &bot->chat_id) || bot->chat_id <= 0) return false;
  const char *p = bot->token;
  if (*p < '0' || *p > '9') return false;
  while (*p >= '0' && *p <= '9') ++p;
  if (*p++ != ':' || !*p) return false;
  for (; *p; ++p) {
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') ||
          (*p >= 'A' && *p <= 'Z') || *p == '_' || *p == '-')) return false;
  }
  return true;
}

static unsigned long send_photo(Telegram *bot, const char *caption, const char *keyboard, Json *result) {
  DWORD photo_size = 0;
  const void *photo = resource(IDR_RECEIPT_CAT, &photo_size);
  if (!photo) return ERROR_RESOURCE_DATA_NOT_FOUND;
  char boundary[64], header[2048], tail[80];
  wchar_t content_type[160];
  snprintf(boundary, sizeof(boundary), "meoware-%s", bot->reference);
  swprintf(content_type, 160, L"Content-Type: multipart/form-data; boundary=%hs\r\n", boundary);
  int head_size = snprintf(header, sizeof(header),
    "--%s\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n%lld\r\n"
    "--%s\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n%s\r\n"
    "--%s\r\nContent-Disposition: form-data; name=\"reply_markup\"\r\n\r\n%s\r\n"
    "--%s\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"meoware.png\"\r\n"
    "Content-Type: image/png\r\n\r\n",
    boundary, (long long)bot->chat_id, boundary, caption, boundary, keyboard, boundary);
  int tail_size = snprintf(tail, sizeof(tail), "\r\n--%s--\r\n", boundary);
  if (head_size < 0 || (size_t)head_size >= sizeof(header) || tail_size < 0) return ERROR_INVALID_DATA;
  size_t length = (size_t)head_size + photo_size + (size_t)tail_size;
  char *body = malloc(length);
  if (!body) return ERROR_NOT_ENOUGH_MEMORY;
  memcpy(body, header, head_size);
  memcpy(body + head_size, photo, photo_size);
  memcpy(body + head_size + photo_size, tail, tail_size);
  unsigned long error = request(bot, "sendPhoto", content_type, body, (DWORD)length, result);
  free(body);
  return error;
}

static bool stopped(Telegram *bot) { return WaitForSingleObject(bot->stop, 0) == WAIT_OBJECT_0; }

static DWORD WINAPI run(void *parameter) {
  Telegram *bot = parameter;
  Json result;
  unsigned long error = ERROR_INVALID_DATA;
  int64_t message_id, offset = 0;
  char body[1024], caption[512], keyboard[256], query_id[128] = { 0 };
  if (!configure(bot)) goto done;
  bot->session = WinHttpOpen(L"MeowareDemo/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!bot->session) { error = GetLastError(); goto done; }
  WinHttpSetTimeouts(bot->session, 5000, 5000, 10000, 15000);
  bot->connection = WinHttpConnect(bot->session, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!bot->connection) { error = GetLastError(); goto done; }
  error = call_json(bot, "getWebhookInfo", "{}", &result);
  if (error) goto done;
  char webhook[2048];
  if (!json_string(json_get(result, "url"), webhook, sizeof(webhook)) || webhook[0]) { error = 409; goto done; }
  if (stopped(bot)) goto done;
  snprintf(caption, sizeof(caption), "MEOWCOINS - DEMO PAYMENT REQUEST\n=^..^=\n\n"
    "Reference: %s\nAmount: 25 meowcoins\n\nApprove this simulation to restore the five lab samples.", bot->reference);
  snprintf(keyboard, sizeof(keyboard), "{\"inline_keyboard\":[[{\"text\":\"Payment: OK - send receipt\","
    "\"callback_data\":\"meow:%s\"}]]}", bot->reference);
  error = send_photo(bot, caption, keyboard, &result);
  if (error) goto done;
  if (!json_integer(json_get(result, "message_id"), &message_id)) { error = ERROR_INVALID_DATA; goto done; }
  PostMessageA(bot->window, WM_TELEGRAM, TELEGRAM_WAITING, 0);
  while (!stopped(bot) && !query_id[0]) {
    snprintf(body, sizeof(body), "{\"offset\":%lld,\"timeout\":5,\"limit\":100,\"allowed_updates\":[\"callback_query\"]}", (long long)offset);
    error = call_json(bot, "getUpdates", body, &result);
    if (error) goto done;
    if (!result.size || result.text[0] != '[') { error = ERROR_INVALID_DATA; goto done; }
    for (size_t i = 0; i < 100; ++i) {
      Json update = json_at(result, i);
      int64_t id;
      if (!update.size) break;
      if (!json_integer(json_get(update, "update_id"), &id) || id < 0 || id == INT64_MAX) {
        error = ERROR_INVALID_DATA; goto done;
      }
      offset = id + 1;
      if (approval_matches(json_get(update, "callback_query"), bot->chat_id, message_id, bot->reference, query_id)) break;
      query_id[0] = 0;
    }
  }
  if (stopped(bot)) goto done;
  snprintf(body, sizeof(body), "{\"callback_query_id\":\"%s\",\"text\":\"Demo receipt approved =^..^=\"}", query_id);
  /* The approval remains valid if the optional toast has expired. */
  call_json(bot, "answerCallbackQuery", body, &result);
  snprintf(body, sizeof(body), "{\"chat_id\":%lld,\"message_id\":%lld,\"reply_markup\":{\"inline_keyboard\":[]}}",
    (long long)bot->chat_id, (long long)message_id);
  call_json(bot, "editMessageReplyMarkup", body, &result);
  if (stopped(bot)) goto done;
  snprintf(caption, sizeof(caption), "MEOWCOINS - DEMO RECEIPT\n=^..^=\n\n"
    "Receipt: MEOWARE-DEMO-%s\nAmount: 25 meowcoins\nStatus: approved by the lab operator\n\n"
    "Fictional meowcoins. No real payment.", bot->reference);
  error = send_photo(bot, caption, "{\"inline_keyboard\":[]}", &result);
  if (!error && !json_integer(json_get(result, "message_id"), &message_id)) error = ERROR_INVALID_DATA;
  if (!error && !stopped(bot)) PostMessageA(bot->window, WM_TELEGRAM, TELEGRAM_APPROVED, 0);
done:
  if (error && !stopped(bot)) PostMessageA(bot->window, WM_TELEGRAM, TELEGRAM_FAILED, (LPARAM)error);
  if (bot->connection) WinHttpCloseHandle(bot->connection);
  if (bot->session) WinHttpCloseHandle(bot->session);
  SecureZeroMemory(bot, sizeof(*bot));
  free(bot);
  return 0;
}

bool telegram_start(HWND window, char reference[33]) {
  if (worker && WaitForSingleObject(worker, 0) != WAIT_OBJECT_0) return false;
  if (worker) { CloseHandle(worker); worker = NULL; }
  if (stop_event) { CloseHandle(stop_event); stop_event = NULL; }
  Telegram *bot = calloc(1, sizeof(*bot));
  unsigned char random[16];
  if (!bot) return false;
  if (!crypto_random(random, sizeof(random))) { free(bot); return false; }
  for (size_t i = 0; i < sizeof(random); ++i) snprintf(bot->reference + 2 * i, 3, "%02x", random[i]);
  memcpy(reference, bot->reference, 33);
  bot->window = window;
  stop_event = bot->stop = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (!stop_event) { free(bot); return false; }
  worker = CreateThread(NULL, 0, run, bot, 0, NULL);
  if (!worker) { CloseHandle(stop_event); stop_event = NULL; free(bot); return false; }
  return true;
}

void telegram_cancel(void) { if (stop_event) SetEvent(stop_event); }

const char *telegram_error(unsigned long code) {
  switch (code) {
  case 400: return "Telegram rejected the request. Check the configured chat ID and send /start to the bot.";
  case 401: case 404: return "Telegram token is invalid. Update bot/config.json and rebuild.";
  case 403: return "Open the bot in Telegram, unblock it if needed, and send /start.";
  case 409: return "Stop other clients using this bot token. Only this GUI may poll updates; disable any webhook.";
  case 429: return "Telegram rate limit reached. Wait before retrying.";
  case ERROR_INVALID_DATA: return "Invalid bot configuration or Telegram response. Check bot/config.json and rebuild.";
  default: return "Telegram request failed. Check network access, then click Retry transfer. Local restore is still available.";
  }
}
