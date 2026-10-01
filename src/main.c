/* author: cocomelonc */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "lab.h"
#include "receipt.h"
#include "resource.h"

#define ID_RUN     1001
#define ID_RESTORE   1002
#define ID_NOTE    1003
#define ID_TRANSFER 1004
#define ID_RECEIPT  1005
#define ID_VIEW     1006
#define ID_ALGORITHM 1007
#define ID_TIMER   1
#define COUNTDOWN_SECONDS (24UL * 60UL * 60UL)
#define LOG_CAPACITY 6

static const char *WINDOW_CLASS = "MeowareEduWindow";
static const char *sample_names[LAB_SAMPLE_COUNT] = {
  "sample1.txt", "sample2.txt", "sample3.txt", "sample4.txt", "sample5.txt"
};

typedef enum {
  DEMO_READY,
  DEMO_RUNNING,
  DEMO_RESTORED,
  DEMO_EXPIRED,
  DEMO_ERROR
} DemoState;

typedef struct {
  char time[12];
  char text[160];
} LogEntry;

static LabSession g_lab;
static HWND g_run_button;
static HWND g_restore_button;
static HWND g_note_button;
static HWND g_transfer_button;
static HWND g_receipt_button;
static HWND g_view_button;
static HWND g_algorithm_picker;
static CryptoAlgorithm g_selected_algorithm = CRYPTO_AES256_CBC;
static DemoReceipt g_receipt;
static bool g_payment_view = true;
static HFONT g_font_title;
static HFONT g_font_countdown;
static HFONT g_font_heading;
static HFONT g_font_body;
static HFONT g_font_small;
static HFONT g_font_mono;
static HWND g_hover_button;
static WNDPROC g_button_proc;
static ULONGLONG g_deadline;
static ULONGLONG g_started;
static bool g_timer_running;
static bool g_lab_ready;
static DemoState g_state = DEMO_READY;
static LogEntry g_log[LOG_CAPACITY];
static unsigned int g_log_count;

static void update_buttons(void);
static void on_deadline(HWND window);

enum {
  COLOR_BG = RGB(247, 245, 250),
  COLOR_PANEL = RGB(255, 254, 255),
  COLOR_PANEL_ALT = RGB(239, 233, 247),
  COLOR_BORDER = RGB(227, 220, 236),
  COLOR_TEXT = RGB(57, 49, 70),
  COLOR_MUTED = RGB(112, 102, 124),
  COLOR_ACCENT = RGB(119, 91, 158),
  COLOR_ACCENT_DARK = RGB(94, 68, 130),
  COLOR_TEAL = RGB(52, 116, 98),
  COLOR_RED = RGB(164, 70, 94),
  COLOR_MINT = RGB(229, 243, 236),
  COLOR_ROSE = RGB(250, 233, 237),
  COLOR_TRACK = RGB(233, 226, 241),
  COLOR_SHADOW = RGB(237, 232, 243)
};

static COLORREF state_color(void) {
  switch (g_state) {
  case DEMO_RUNNING: return COLOR_RED;
  case DEMO_RESTORED: return COLOR_TEAL;
  case DEMO_EXPIRED: return COLOR_RED;
  case DEMO_ERROR: return COLOR_RED;
  default: return COLOR_ACCENT;
  }
}

static COLORREF state_tint(void) {
  switch (g_state) {
  case DEMO_RUNNING:
  case DEMO_EXPIRED:
  case DEMO_ERROR: return COLOR_ROSE;
  case DEMO_RESTORED: return COLOR_MINT;
  default: return COLOR_PANEL_ALT;
  }
}

static const char *state_text(void) {
  switch (g_state) {
  case DEMO_RUNNING: return "ENCRYPTED - RESTORE AVAILABLE";
  case DEMO_RESTORED: return "RESTORED - LAB COMPLETE";
  case DEMO_EXPIRED: return "DEADLINE - DEMO FILES REMOVED";
  case DEMO_ERROR: return "LAB INITIALIZATION ERROR";
  default: return "READY - ISOLATED LAB";
  }
}

static void add_log(const char *text) {
  SYSTEMTIME now;
  unsigned int i;

  if (g_log_count == LOG_CAPACITY) {
    for (i = 1; i < LOG_CAPACITY; ++i) g_log[i - 1] = g_log[i];
    --g_log_count;
  }
  GetLocalTime(&now);
  snprintf(g_log[g_log_count].time, sizeof(g_log[g_log_count].time),
       "%02u:%02u", (unsigned int)now.wHour, (unsigned int)now.wMinute);
  snprintf(g_log[g_log_count].text, sizeof(g_log[g_log_count].text), "%s", text);
  ++g_log_count;
}

static int show_message(HWND window, const char *message, const char *title) {
  MSGBOXPARAMSA options = { 0 };
  options.cbSize = sizeof(options);
  options.hwndOwner = window;
  options.hInstance = GetModuleHandleA(NULL);
  options.lpszText = message;
  options.lpszCaption = title;
  options.dwStyle = MB_OK | MB_USERICON;
  options.lpszIcon = MAKEINTRESOURCEA(IDI_MEOWARE);
  return MessageBoxIndirectA(&options);
}

static void show_error(HWND window, const char *message) {
  g_state = DEMO_ERROR;
  receipt_close(&g_receipt);
  update_buttons();
  add_log("An operation failed; review the message.");
  InvalidateRect(window, NULL, FALSE);
  show_message(window, message, "Meoware EDU - error");
}

static void update_buttons(void) {
  EnableWindow(g_algorithm_picker, g_lab_ready && g_state == DEMO_READY);
  if (g_run_button != NULL) {
    EnableWindow(g_run_button, g_lab_ready && g_state == DEMO_READY);
  }
  if (g_restore_button != NULL) {
    EnableWindow(g_restore_button, g_lab_ready && g_state == DEMO_RUNNING);
  }
  if (g_run_button != NULL) InvalidateRect(g_run_button, NULL, TRUE);
  if (g_restore_button != NULL) InvalidateRect(g_restore_button, NULL, TRUE);
  if (g_note_button != NULL) InvalidateRect(g_note_button, NULL, TRUE);
  EnableWindow(g_transfer_button, g_state == DEMO_RUNNING && g_receipt.phase == RECEIPT_WAITING);
  EnableWindow(g_receipt_button, g_state == DEMO_RUNNING);
  ShowWindow(g_transfer_button, g_payment_view ? SW_SHOWNA : SW_HIDE);
  ShowWindow(g_receipt_button, g_payment_view ? SW_SHOWNA : SW_HIDE);
  SetWindowTextA(g_view_button, g_payment_view ? "Show activity" : "Payment demo");
  InvalidateRect(g_transfer_button, NULL, FALSE);
  InvalidateRect(g_receipt_button, NULL, FALSE);
  InvalidateRect(g_view_button, NULL, FALSE);
}

static void on_run(HWND window) {
  char error[256];
  char event[160];

  if (!g_lab_ready || g_state != DEMO_READY) return;
  if (!lab_encrypt_samples(&g_lab, g_selected_algorithm, error, sizeof(error))) {
    show_error(window, error);
    return;
  }
  g_started = GetTickCount64();
  g_deadline = g_started + (ULONGLONG)COUNTDOWN_SECONDS * 1000;
  g_timer_running = true;
  g_state = DEMO_RUNNING;
  receipt_open(&g_receipt);
  SetTimer(window, ID_TIMER, 1000, NULL);
  update_buttons();
  snprintf(event, sizeof(event), "Five samples encrypted with %s.",
    crypto_algorithm_info(g_lab.crypto.selected)->name);
  add_log(event);
  add_log("Encrypted copies use the .meoware extension.");
  InvalidateRect(window, NULL, FALSE);
}

static void on_restore(HWND window) {
  char error[256];

  if (!g_lab_ready || g_state != DEMO_RUNNING) return;
  if (GetTickCount64() >= g_deadline) {
    on_deadline(window);
    return;
  }
  if (!lab_restore_samples(&g_lab, error, sizeof(error))) {
    show_error(window, error);
    return;
  }
  if (g_timer_running) {
    KillTimer(window, ID_TIMER);
    g_timer_running = false;
  }
  g_state = DEMO_RESTORED;
  receipt_close(&g_receipt);
  update_buttons();
  add_log("All five samples restored using the session key.");
  InvalidateRect(window, NULL, FALSE);
}

static void on_note(HWND window) {
  show_message(window,
        "EDUCATIONAL RANSOMWARE BEHAVIOR LAB\r\n\r\n"
        "This demonstration encrypts five bundled sample files inside its own private CryptPath folder.\r\n\r\n"
        "Payment demo uses 25 fictional meowcoins. Simulate transfer, wait for three local confirmations, then Check receipt to restore the samples. No real money or blockchain is involved.\r\n\r\n"
        "Restore samples also recovers the files directly. The deadline scenario affects only these generated demo files.",
        "Meoware EDU - demonstration note");
}

static void on_deadline(HWND window) {
  char error[256];

  KillTimer(window, ID_TIMER);
  g_timer_running = false;
  receipt_close(&g_receipt);
  if (lab_expire_samples(&g_lab, error, sizeof(error))) {
    g_state = DEMO_EXPIRED;
    update_buttons();
    add_log("Deadline reached; generated encrypted samples removed.");
    InvalidateRect(window, NULL, FALSE);
    show_message(window,
          "The deadline scenario removed only the five sample files generated in this lab folder.",
          "Meoware EDU - deadline");
  } else {
    show_error(window, error);
  }
}

static bool payment_session_active(HWND window) {
  if (!g_lab_ready || g_state != DEMO_RUNNING) return false;
  if (GetTickCount64() >= g_deadline) {
    on_deadline(window);
    return false;
  }
  return true;
}

static void refresh_receipt(HWND window) {
  if (receipt_advance(&g_receipt, GetTickCount64())) {
    if (g_receipt.phase == RECEIPT_CONFIRMED) {
      add_log("Mock receipt confirmed. Check receipt to restore.");
    }
    InvalidateRect(window, NULL, FALSE);
  }
}

static void on_transfer(HWND window) {
  if (!payment_session_active(window)) return;
  if (!receipt_submit(&g_receipt, GetTickCount64())) return;
  add_log("Fictional meowcoins submitted; confirmations pending.");
  update_buttons();
  InvalidateRect(window, NULL, FALSE);
}

static void on_receipt(HWND window) {
  if (!payment_session_active(window)) return;
  refresh_receipt(window);
  if (g_receipt.phase == RECEIPT_CONFIRMED) {
    add_log("Mock receipt accepted; restoring lab samples.");
    on_restore(window);
  } else {
    const char *explanation = g_receipt.phase == RECEIPT_WAITING
      ? "No mock transfer yet. Click Simulate transfer first."
      : "Mock transfer pending. Wait for 3/3 confirmations.";
    add_log(explanation);
    InvalidateRect(window, NULL, FALSE);
    show_message(window, explanation, "Meoware EDU - mock receipt");
  }
}

static void set_font(HDC dc, HFONT font) {
  if (font != NULL) SelectObject(dc, font);
}

static HFONT create_mono_font(int height, int weight) {
  HDC dc = GetDC(NULL);
  const char *faces[] = { "Consolas", "Courier New" };
  HFONT font = NULL;
  unsigned int i;

  for (i = 0; i < sizeof(faces) / sizeof(faces[0]); ++i) {
    char actual_face[LF_FACESIZE] = { 0 };
    HGDIOBJ previous;
    font = CreateFontA(-height, 0, 0, 0, weight, FALSE, FALSE, FALSE,
      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
      CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, faces[i]);
    if (font == NULL || dc == NULL) break;
    previous = SelectObject(dc, font);
    GetTextFaceA(dc, sizeof(actual_face), actual_face);
    SelectObject(dc, previous);
    if (lstrcmpiA(actual_face, faces[i]) == 0 || i == 1) break;
    DeleteObject(font);
    font = NULL;
  }
  if (dc != NULL) ReleaseDC(NULL, dc);
  return font;
}

static void draw_text(HDC dc, const char *text, int x, int y, int width, int height,
            COLORREF color, HFONT font, UINT format) {
  RECT rect = { x, y, x + width, y + height };
  SetBkMode(dc, TRANSPARENT);
  SetTextColor(dc, color);
  set_font(dc, font);
  DrawTextA(dc, text, -1, &rect, format | DT_NOPREFIX);
}

static void fill_round_rect(HDC dc, int x, int y, int width, int height,
              int radius, COLORREF fill, COLORREF border) {
  HBRUSH brush = CreateSolidBrush(fill);
  HPEN pen = CreatePen(PS_SOLID, 1, border);
  HGDIOBJ old_brush = SelectObject(dc, brush);
  HGDIOBJ old_pen = SelectObject(dc, pen);

  RoundRect(dc, x, y, x + width, y + height, radius, radius);
  SelectObject(dc, old_brush);
  SelectObject(dc, old_pen);
  DeleteObject(brush);
  DeleteObject(pen);
}

static void fill_rect(HDC dc, int x, int y, int width, int height, COLORREF color) {
  RECT rect = { x, y, x + width, y + height };
  HBRUSH brush = CreateSolidBrush(color);
  FillRect(dc, &rect, brush);
  DeleteObject(brush);
}

static void draw_card(HDC dc, int x, int y, int width, int height) {
  fill_round_rect(dc, x, y + 3, width, height, 22, COLOR_SHADOW, COLOR_SHADOW);
  fill_round_rect(dc, x, y, width, height, 22, COLOR_PANEL, COLOR_BORDER);
}

static void draw_status_dot(HDC dc, int x, int y, COLORREF color) {
  HBRUSH brush = CreateSolidBrush(color);
  HGDIOBJ old_brush = SelectObject(dc, brush);
  HGDIOBJ old_pen = SelectObject(dc, GetStockObject(NULL_PEN));
  Ellipse(dc, x, y, x + 9, y + 9);
  SelectObject(dc, old_pen);
  SelectObject(dc, old_brush);
  DeleteObject(brush);
}

static void draw_payment(HDC dc, int x) {
  char summary[100];
  const char *hint;
  COLORREF ink = g_receipt.phase == RECEIPT_CONFIRMED ? COLOR_TEAL : COLOR_ACCENT_DARK;
  unsigned int step;

  switch (g_receipt.phase) {
  case RECEIPT_WAITING: hint = "Awaiting a simulated transfer."; break;
  case RECEIPT_PENDING: hint = "Confirming locally / one step every 2 seconds."; break;
  case RECEIPT_CONFIRMED: hint = "Receipt ready. Check receipt to restore samples."; break;
  case RECEIPT_CLOSED:
    hint = g_state == DEMO_RESTORED ? "Samples restored / session complete." : "Session closed / transfers unavailable.";
    break;
  default: hint = "Run demo to start the payment scenario."; break;
  }
  draw_text(dc, "PAYMENT DEMO", x + 22, 369, 456, 23,
    COLOR_TEXT, g_font_heading, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "Fictional meowcoins only / no real payment", x + 22, 394, 456, 18,
    COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  snprintf(summary, sizeof(summary), "Amount: %u meowcoins / Received: %u", RECEIPT_DEMO_UNITS, g_receipt.credited_units);
  draw_text(dc, summary, x + 22, 425, 456, 22,
    COLOR_TEXT, g_font_mono, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "Destination: demo://meoware/local-session", x + 22, 453, 456, 20,
    COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  snprintf(summary, sizeof(summary), "Confirmations: %u / %u", g_receipt.confirmations, RECEIPT_STEPS);
  draw_text(dc, summary, x + 22, 482, 456, 20,
    ink, g_font_mono, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  for (step = 0; step < RECEIPT_STEPS; ++step) {
    COLORREF color = step < g_receipt.confirmations ? COLOR_TEAL : COLOR_TRACK;
    fill_round_rect(dc, x + 22 + (int)step * 154, 512, 146, 5, 4, color, color);
  }
  draw_text(dc, hint, x + 22, 530, 456, 30,
    ink, g_font_small, DT_LEFT | DT_WORDBREAK);
}

static void draw_dashboard(HWND window, HDC dc) {
  RECT client;
  char countdown[32];
  char path_text[MAX_PATH + 32];
  char algorithm_text[100];
  const CryptoInfo *algorithm = crypto_algorithm_info(
    g_lab.crypto.initialized ? g_lab.crypto.selected : g_selected_algorithm);
  ULONGLONG seconds = 24UL * 60UL * 60UL;
  int client_width;
  int left_x = 28;
  int right_x;
  int card_width;
  int i;

  GetClientRect(window, &client);
  client_width = client.right - client.left;
  right_x = client_width - 28 - 500;
  card_width = right_x - left_x - 20;
  if (card_width < 350) card_width = 350;
  if (right_x < left_x + card_width + 20) right_x = left_x + card_width + 20;

  fill_rect(dc, 0, 0, client_width, client.bottom, COLOR_BG);

  fill_round_rect(dc, 29, 24, 80, 44, 16, COLOR_PANEL_ALT, COLOR_BORDER);
  draw_text(dc, "=^..^=", 29, 27, 80, 36, COLOR_ACCENT_DARK, g_font_heading,
        DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "MEOWARE", 124, 22, 260, 32, COLOR_TEXT, g_font_title,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "EDU  /  BEHAVIOR LAB", 126, 57, 430, 20,
        COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  fill_round_rect(dc, client_width - 190, 31, 160, 30, 15,
          COLOR_MINT, COLOR_MINT);
  draw_status_dot(dc, client_width - 174, 42, COLOR_TEAL);
  draw_text(dc, "LOCAL DEMO", client_width - 158, 36, 116, 20,
        COLOR_TEAL, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  fill_rect(dc, 28, 83, client_width - 56, 1, COLOR_BORDER);

  draw_card(dc, left_x, 105, card_width, 156);
  draw_text(dc, "SESSION COUNTDOWN", left_x + 22, 123, card_width - 44, 18,
        COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  if (g_timer_running) {
    ULONGLONG now = GetTickCount64();
    seconds = (g_deadline > now ? g_deadline - now : 0) / 1000;
    snprintf(countdown, sizeof(countdown), "%02llu:%02llu:%02llu",
         seconds / 3600, (seconds / 60) % 60, seconds % 60);
  } else if (g_state == DEMO_RESTORED) {
    snprintf(countdown, sizeof(countdown), "COMPLETE");
  } else if (g_state == DEMO_EXPIRED) {
    snprintf(countdown, sizeof(countdown), "00:00:00");
  } else {
    snprintf(countdown, sizeof(countdown), "24:00:00");
  }
  draw_text(dc, countdown, left_x + 20, 146, card_width - 40, 54,
        COLOR_ACCENT_DARK, g_font_countdown, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, g_timer_running ? "Time remaining in this demonstration" : "A 24-hour behavior window starts with the demo",
        left_x + 23, 204, card_width - 46, 19, COLOR_MUTED, g_font_small,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  fill_round_rect(dc, left_x + 23, 233, card_width - 46, 5, 4, COLOR_TRACK, COLOR_TRACK);
  if (g_timer_running) {
    ULONGLONG elapsed = GetTickCount64() > g_started ? GetTickCount64() - g_started : 0;
    int progress = (int)((card_width - 46) * elapsed /
              ((ULONGLONG)COUNTDOWN_SECONDS * 1000));
    if (progress > card_width - 46) progress = card_width - 46;
    if (progress > 0) {
      fill_round_rect(dc, left_x + 23, 233, progress, 5, 4, COLOR_ACCENT, COLOR_ACCENT);
    }
  } else if (g_state == DEMO_RESTORED || g_state == DEMO_EXPIRED) {
    fill_round_rect(dc, left_x + 23, 233, card_width - 46, 5, 4,
            state_color(), state_color());
  }

  draw_card(dc, right_x, 105, 500, 156);
  draw_text(dc, "LAB STATUS", right_x + 22, 123, 456, 18,
        COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  fill_round_rect(dc, right_x + 21, 150, 456, 30, 15,
          state_tint(), state_tint());
  draw_status_dot(dc, right_x + 33, 160, state_color());
  draw_text(dc, state_text(), right_x + 50, 154, 420, 22,
        state_color(), g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "Scope", right_x + 23, 193, 60, 18,
        COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "5 samples / private folder / offline",
        right_x + 85, 193, 392, 18, COLOR_TEXT, g_font_small,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  snprintf(algorithm_text, sizeof(algorithm_text), "%s / key %u-bit / block %u-bit",
    algorithm->name, algorithm->key_size * 8, algorithm->block_size * 8);
  draw_text(dc, algorithm_text, right_x + 23, 220, 456, 18,
        COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "ALGORITHM", 790, 267, 262, 17, COLOR_MUTED,
    g_font_small, DT_LEFT | DT_SINGLELINE);

  draw_card(dc, left_x, 351, card_width, 277);
  draw_text(dc, "SAMPLE FILES", left_x + 22, 369, card_width - 44, 23,
        COLOR_TEXT, g_font_heading, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  draw_text(dc, "Bundled educational sample files", left_x + 22, 394,
        card_width - 44, 18, COLOR_MUTED, g_font_small,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  for (i = 0; i < LAB_SAMPLE_COUNT; ++i) {
    int row_y = 431 + i * 35;
    COLORREF dot = COLOR_TEAL;
    COLORREF tint = COLOR_MINT;
    const char *status = "READY";
    if (g_state == DEMO_RUNNING) {
      dot = COLOR_RED;
      tint = COLOR_ROSE;
      status = "ENCRYPTED";
    } else if (g_state == DEMO_RESTORED) {
      dot = COLOR_ACCENT_DARK;
      tint = COLOR_PANEL_ALT;
      status = "RESTORED";
    } else if (g_state == DEMO_EXPIRED) {
      dot = COLOR_RED;
      tint = COLOR_ROSE;
      status = "REMOVED";
    }
    draw_status_dot(dc, left_x + 23, row_y + 6, dot);
    draw_text(dc, sample_names[i], left_x + 43, row_y, 190, 22,
          COLOR_TEXT, g_font_mono, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill_round_rect(dc, left_x + card_width - 119, row_y + 1, 91, 22,
            11, tint, tint);
    draw_text(dc, status, left_x + card_width - 115, row_y + 2, 83, 19,
          dot, g_font_small, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if (i != LAB_SAMPLE_COUNT - 1) {
      fill_rect(dc, left_x + 22, row_y + 29, card_width - 44, 1, COLOR_BORDER);
    }
  }

  draw_card(dc, right_x, 351, 500, 277);
  if (g_payment_view) {
    draw_payment(dc, right_x);
  } else {
    draw_text(dc, "ACTIVITY", right_x + 22, 369, 385, 23,
          COLOR_TEXT, g_font_heading, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    draw_text(dc, "Local events from this session", right_x + 22, 394, 385, 18,
          COLOR_MUTED, g_font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    for (i = 0; i < (int)g_log_count; ++i) {
      int row_y = 432 + i * 30;
      draw_text(dc, g_log[i].time, right_x + 22, row_y, 48, 20,
            COLOR_ACCENT, g_font_mono, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
      draw_text(dc, g_log[i].text, right_x + 78, row_y, 400, 28,
            COLOR_TEXT, g_font_small, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS);
    }
  }

  fill_round_rect(dc, 28, 646, client_width - 56, 36, 12,
          COLOR_PANEL_ALT, COLOR_PANEL_ALT);
  draw_text(dc, "PRIVATE LAB", 42, 655, 100, 18, COLOR_ACCENT_DARK, g_font_small,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  snprintf(path_text, sizeof(path_text), "%s", g_lab_ready ? lab_directory(&g_lab) : "Lab folder unavailable");
  draw_text(dc, path_text, 152, 655, client_width - 198, 18, COLOR_MUTED,
        g_font_mono, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_PATH_ELLIPSIS);
}

static void draw_button(const DRAWITEMSTRUCT *item)
{
  HDC dc = item->hDC;
  RECT r = item->rcItem;
  bool disabled = (item->itemState & ODS_DISABLED) != 0;
  bool pressed = (item->itemState & ODS_SELECTED) != 0;
  bool hovered = g_hover_button == item->hwndItem && !disabled;
  COLORREF fill;
  COLORREF border;
  COLORREF text_color;
  char label[40];
  int width = r.right - r.left;
  int height = r.bottom - r.top;

  bool payment_control = item->CtlID == ID_TRANSFER || item->CtlID == ID_RECEIPT;
  GetWindowTextA(item->hwndItem, label, sizeof(label));
  fill_rect(dc, r.left, r.top, width, height, payment_control ? COLOR_PANEL : COLOR_BG);

  if (item->CtlID == ID_RUN || item->CtlID == ID_TRANSFER) {
    fill = disabled ? COLOR_PANEL_ALT : (hovered ? COLOR_ACCENT_DARK : COLOR_ACCENT);
    border = disabled ? COLOR_BORDER : COLOR_ACCENT;
    text_color = disabled ? COLOR_MUTED : RGB(255, 255, 255);
  } else if (item->CtlID == ID_RESTORE || item->CtlID == ID_RECEIPT) {
    fill = disabled ? COLOR_PANEL : (hovered ? COLOR_MINT : COLOR_PANEL_ALT);
    border = disabled ? COLOR_BORDER : COLOR_ACCENT;
    text_color = disabled ? COLOR_MUTED : COLOR_ACCENT_DARK;
  } else {
    fill = pressed || hovered ? COLOR_PANEL_ALT : COLOR_PANEL;
    border = COLOR_BORDER;
    text_color = disabled ? COLOR_MUTED : COLOR_TEXT;
  }
  if (pressed && !disabled && item->CtlID != ID_NOTE) {
    fill = COLOR_ACCENT_DARK;
    text_color = RGB(255, 255, 255);
  }
  fill_round_rect(dc, r.left, r.top, width, height, 16, fill, border);
  SetBkMode(dc, TRANSPARENT);
  SetTextColor(dc, text_color);
  set_font(dc, g_font_body);
  DrawTextA(dc, label, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
  if ((item->itemState & ODS_FOCUS) && !(item->itemState & ODS_NOFOCUSRECT)) {
    InflateRect(&r, -5, -5);
    DrawFocusRect(dc, &r);
  }
}

static LRESULT CALLBACK button_proc(HWND button, UINT message, WPARAM wparam, LPARAM lparam) {
  if (message == WM_MOUSEMOVE && g_hover_button != button) {
    TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, button, 0 };
    HWND previous = g_hover_button;
    g_hover_button = button;
    TrackMouseEvent(&track);
    if (previous != NULL) InvalidateRect(previous, NULL, FALSE);
    InvalidateRect(button, NULL, FALSE);
  } else if (message == WM_MOUSELEAVE && g_hover_button == button) {
    g_hover_button = NULL;
    InvalidateRect(button, NULL, FALSE);
  }
  return CallWindowProcA(g_button_proc, button, message, wparam, lparam);
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
  switch (message) {
  case WM_CREATE: {
    char error[256];
    size_t algorithm_index;

    g_run_button = CreateWindowExA(0, "BUTTON", "Run demo",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 28, 286, 160, 44,
      window, (HMENU)(INT_PTR)ID_RUN, GetModuleHandleA(NULL), NULL);
    g_restore_button = CreateWindowExA(0, "BUTTON", "Restore samples",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 200, 286, 200, 44,
      window, (HMENU)(INT_PTR)ID_RESTORE, GetModuleHandleA(NULL), NULL);
    g_note_button = CreateWindowExA(0, "BUTTON", "View note",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 412, 286, 160, 44,
      window, (HMENU)(INT_PTR)ID_NOTE, GetModuleHandleA(NULL), NULL);
    g_view_button = CreateWindowExA(0, "BUTTON", "Show activity",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 584, 286, 180, 44,
      window, (HMENU)(INT_PTR)ID_VIEW, GetModuleHandleA(NULL), NULL);
    g_transfer_button = CreateWindowExA(0, "BUTTON", "Simulate transfer",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 574, 571, 222, 38,
      window, (HMENU)(INT_PTR)ID_TRANSFER, GetModuleHandleA(NULL), NULL);
    g_receipt_button = CreateWindowExA(0, "BUTTON", "Check receipt",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 808, 571, 222, 38,
      window, (HMENU)(INT_PTR)ID_RECEIPT, GetModuleHandleA(NULL), NULL);
    g_algorithm_picker = CreateWindowExA(0, "COMBOBOX", "Algorithm",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
      790, 291, 262, 180, window, (HMENU)(INT_PTR)ID_ALGORITHM,
      GetModuleHandleA(NULL), NULL);
    SendMessageA(g_algorithm_picker, WM_SETFONT, (WPARAM)g_font_body, TRUE);
    for (algorithm_index = 0; algorithm_index < crypto_algorithm_count(); ++algorithm_index) {
      const CryptoInfo *entry = crypto_algorithm_at(algorithm_index);
      LRESULT row = SendMessageA(g_algorithm_picker, CB_ADDSTRING, 0, (LPARAM)entry->name);
      if (row >= 0) SendMessageA(g_algorithm_picker, CB_SETITEMDATA, (WPARAM)row, entry->id);
    }
    SendMessageA(g_algorithm_picker, CB_SETCURSEL, 0, 0);
    g_button_proc = (WNDPROC)SetWindowLongPtrA(g_run_button, GWLP_WNDPROC, (LONG_PTR)button_proc);
    SetWindowLongPtrA(g_restore_button, GWLP_WNDPROC, (LONG_PTR)button_proc);
    SetWindowLongPtrA(g_note_button, GWLP_WNDPROC, (LONG_PTR)button_proc);
    SetWindowLongPtrA(g_view_button, GWLP_WNDPROC, (LONG_PTR)button_proc);
    SetWindowLongPtrA(g_transfer_button, GWLP_WNDPROC, (LONG_PTR)button_proc);
    SetWindowLongPtrA(g_receipt_button, GWLP_WNDPROC, (LONG_PTR)button_proc);
    EnableWindow(g_restore_button, FALSE);
    if (!lab_initialize(&g_lab, error, sizeof(error))) {
      show_error(window, error);
      add_log("Lab initialization failed.");
    } else {
      g_lab_ready = true;
      add_log("Created isolated folder and five bundled samples.");
      add_log("Ready - only these generated samples are in scope.");
    }
    update_buttons();
    return 0;
  }
  case WM_COMMAND:
    switch (LOWORD(wparam)) {
    case ID_ALGORITHM:
      if (HIWORD(wparam) == CBN_SELCHANGE && g_state == DEMO_READY) {
        LRESULT row = SendMessageA(g_algorithm_picker, CB_GETCURSEL, 0, 0);
        CryptoAlgorithm selected = (CryptoAlgorithm)SendMessageA(g_algorithm_picker, CB_GETITEMDATA, (WPARAM)row, 0);
        if (crypto_algorithm_info(selected) != NULL) g_selected_algorithm = selected;
        InvalidateRect(window, NULL, FALSE);
      }
      return 0;
    case ID_RUN: on_run(window); return 0;
    case ID_RESTORE: on_restore(window); return 0;
    case ID_NOTE: on_note(window); return 0;
    case ID_TRANSFER: on_transfer(window); return 0;
    case ID_RECEIPT: on_receipt(window); return 0;
    case ID_VIEW:
      g_payment_view = !g_payment_view;
      update_buttons();
      InvalidateRect(window, NULL, FALSE);
      return 0;
    }
    break;
  case WM_DRAWITEM:
    if (wparam == ID_RUN || wparam == ID_RESTORE || wparam == ID_NOTE ||
        wparam == ID_TRANSFER || wparam == ID_RECEIPT || wparam == ID_VIEW) {
      draw_button((const DRAWITEMSTRUCT *)lparam);
      return TRUE;
    }
    break;
  case WM_TIMER:
    if (wparam == ID_TIMER && g_timer_running) {
      if (GetTickCount64() >= g_deadline) on_deadline(window);
      else {
        refresh_receipt(window);
        InvalidateRect(window, NULL, FALSE);
      }
      return 0;
    }
    break;
  case WM_PAINT: {
    PAINTSTRUCT paint;
    HDC dc = BeginPaint(window, &paint);
    RECT client;
    HDC buffer = CreateCompatibleDC(dc);
    HBITMAP bitmap;
    GetClientRect(window, &client);
    bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
    if (buffer != NULL && bitmap != NULL) {
      HGDIOBJ previous = SelectObject(buffer, bitmap);
      draw_dashboard(window, buffer);
      BitBlt(dc, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);
      SelectObject(buffer, previous);
    } else {
      draw_dashboard(window, dc);
    }
    if (bitmap != NULL) DeleteObject(bitmap);
    if (buffer != NULL) DeleteDC(buffer);
    EndPaint(window, &paint);
    return 0;
  }
  case WM_ERASEBKGND:
    return 1;
  case WM_DESTROY:
    if (g_timer_running) KillTimer(window, ID_TIMER);
    lab_close(&g_lab);
    if (g_font_title != NULL) DeleteObject(g_font_title);
    if (g_font_countdown != NULL) DeleteObject(g_font_countdown);
    if (g_font_heading != NULL) DeleteObject(g_font_heading);
    if (g_font_body != NULL) DeleteObject(g_font_body);
    if (g_font_small != NULL) DeleteObject(g_font_small);
    if (g_font_mono != NULL) DeleteObject(g_font_mono);
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcA(window, message, wparam, lparam);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show_command) {
  WNDCLASSEXA window_class;
  HWND window;
  MSG message;
  RECT window_rect = { 0, 0, 1080, 706 };
  DWORD window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;

  (void)previous;
  (void)command_line;
  g_font_title = create_mono_font(30, FW_BOLD);
  g_font_countdown = create_mono_font(44, FW_NORMAL);
  g_font_heading = create_mono_font(16, FW_BOLD);
  g_font_body = create_mono_font(16, FW_NORMAL);
  g_font_small = create_mono_font(13, FW_NORMAL);
  g_font_mono = create_mono_font(14, FW_NORMAL);

  memset(&window_class, 0, sizeof(window_class));
  window_class.cbSize = sizeof(window_class);
  window_class.lpfnWndProc = window_proc;
  window_class.hInstance = instance;
  window_class.hCursor = LoadCursorA(NULL, IDC_ARROW);
  window_class.hIcon = (HICON)LoadImageA(instance, MAKEINTRESOURCEA(IDI_MEOWARE),
    IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_SHARED);
  window_class.hIconSm = (HICON)LoadImageA(instance, MAKEINTRESOURCEA(IDI_MEOWARE),
    IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED);
  window_class.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  window_class.lpszClassName = WINDOW_CLASS;
  if (!RegisterClassExA(&window_class)) return 1;

  AdjustWindowRectEx(&window_rect, window_style, FALSE, 0);
  window = CreateWindowExA(0, WINDOW_CLASS, "Meoware EDU - Behavior Lab",
               window_style,
               CW_USEDEFAULT, CW_USEDEFAULT,
               window_rect.right - window_rect.left, window_rect.bottom - window_rect.top,
               NULL, NULL, instance, NULL);
  if (window == NULL) return 1;
  ShowWindow(window, show_command);
  UpdateWindow(window);

  while (GetMessageA(&message, NULL, 0, 0) > 0) {
    if (!IsDialogMessageA(window, &message)) {
      TranslateMessage(&message);
      DispatchMessageA(&message);
    }
  }
  return (int)message.wParam;
}
