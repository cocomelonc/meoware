"""Telegram meowcoins approval; network activity starts only on a GUI action."""

import json
import os
from pathlib import Path
import re
import secrets
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .core import ROOT


class TelegramError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def configuration(path=None):
    path = Path(path or os.environ.get("MEOWARE_TELEGRAM_CONFIG", ROOT / "bot/config.json"))
    try:
        if path.stat().st_size > 16384:
            raise ValueError
        value = json.loads(path.read_text())
        token, chat_id = value.get("token"), value.get("chat_id")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{1,110}", token):
            raise ValueError
        if type(chat_id) is not int or not 0 < chat_id < 2**63:
            raise ValueError
        return token, chat_id
    except (OSError, ValueError, TypeError, AttributeError):
        raise TelegramError("Configure a dedicated test bot token and positive private chat_id in bot/config.json.") from None


class BotAPI:
    def __init__(self, token):
        self._token = token
        self._opener = build_opener(NoRedirect())

    def call(self, method, payload, photo=None):
        if method not in {"getWebhookInfo", "sendPhoto", "getUpdates", "answerCallbackQuery", "editMessageReplyMarkup"}:
            raise TelegramError("Unsupported Telegram method.")
        if photo is None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            content_type = "application/json"
        else:
            boundary = "meoware-" + secrets.token_hex(16)
            chunks = []
            for key, value in payload.items():
                if not isinstance(value, str):
                    value = json.dumps(value, separators=(",", ":"))
                chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
            chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="meoware.png"\r\nContent-Type: image/png\r\n\r\n').encode())
            chunks += [photo, f"\r\n--{boundary}--\r\n".encode()]
            body, content_type = b"".join(chunks), "multipart/form-data; boundary=" + boundary
        request = Request("https://api.telegram.org/bot" + self._token + "/" + method,
                          data=body, headers={"Content-Type": content_type, "User-Agent": "Meoware-Lab"})
        try:
            with self._opener.open(request, timeout=15) as response:
                raw = response.read(262145)
                if len(raw) > 262144:
                    raise TelegramError("Telegram response exceeds the size limit.")
                value = json.loads(raw)
                if not isinstance(value, dict) or value.get("ok") is not True or "result" not in value:
                    raise TelegramError("Telegram returned an invalid API response.")
                return value["result"]
        except HTTPError as e:
            messages = {400: "Send /start to the configured test bot and check the private chat ID.",
                        401: "The Telegram token is invalid.", 403: "Open or unblock the test bot chat.",
                        404: "The Telegram token is invalid.",
                        409: "Another client or webhook is consuming updates for this bot.",
                        429: "Telegram rate limit reached. Wait before retrying."}
            raise TelegramError(messages.get(e.code, "Telegram HTTP request failed.")) from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise TelegramError("Telegram connection or response failed. Local restore is still available.") from None


class ApprovalFlow:
    def __init__(self, lab, api, chat_id, reference=None, photo=None):
        self.lab, self.api, self.chat_id = lab, api, chat_id
        self.reference = reference or secrets.token_hex(16)
        self.photo = photo if photo is not None else (ROOT / "bot/meoware.png").read_bytes()
        self.receipt = None

    def run(self, cancel, emit):
        webhook = self.api.call("getWebhookInfo", {})
        if not isinstance(webhook, dict) or webhook.get("url") != "":
            raise TelegramError("A webhook is configured. Use a dedicated polling bot; no webhook was changed.")
        if cancel.is_set():
            return False
        keyboard = {"inline_keyboard": [[{"text": "Payment: OK - send receipt",
                                         "callback_data": "meow:" + self.reference}]]}
        message = self.api.call("sendPhoto", {
            "chat_id": self.chat_id,
            "caption": "MEOWCOINS - DEMO PAYMENT REQUEST\n=^..^=\n\nReference: " + self.reference +
                       "\nAmount: 25 meowcoins\n\nApprove this simulation to restore the lab files.",
            "reply_markup": keyboard}, photo=self.photo)
        if not isinstance(message, dict) or type(message.get("message_id")) is not int:
            raise TelegramError("Telegram returned an invalid message ID.")
        message_id, offset = message["message_id"], 0
        emit("waiting", "Awaiting operator approval in the private Telegram chat.")
        query = None
        while not cancel.is_set() and query is None:
            updates = self.api.call("getUpdates", {"offset": offset, "timeout": 5, "limit": 100,
                                                   "allowed_updates": ["callback_query"]})
            if not isinstance(updates, list):
                raise TelegramError("Telegram returned an invalid update list.")
            for update in updates:
                if not isinstance(update, dict) or type(update.get("update_id")) is not int or not 0 <= update["update_id"] < 2**63-1:
                    raise TelegramError("Telegram returned an invalid update ID.")
                if update["update_id"] < offset:
                    continue
                offset = update["update_id"] + 1
                callback = update.get("callback_query", {})
                query = self.lab.approved(callback, self.chat_id, message_id, self.reference)
                if query:
                    break
            if not updates:
                cancel.wait(0.2)
        if cancel.is_set():
            return False
        for method, data in [
            ("answerCallbackQuery", {"callback_query_id": query, "text": "Demo receipt approved =^..^="}),
            ("editMessageReplyMarkup", {"chat_id": self.chat_id, "message_id": message_id,
                                        "reply_markup": {"inline_keyboard": []}}),
        ]:
            try:
                self.api.call(method, data)
            except TelegramError:
                pass
        if cancel.is_set():
            return False
        self.receipt = "MEOWARE-DEMO-" + self.reference
        result = self.api.call("sendPhoto", {
            "chat_id": self.chat_id,
            "caption": "MEOWCOINS - DEMO RECEIPT\n=^..^=\n\nReceipt: " + self.receipt +
                       "\nAmount: 25 meowcoins\nStatus: approved by the lab operator\n\nFictional meowcoins. No real payment.",
            "reply_markup": {"inline_keyboard": []}}, photo=self.photo)
        if not isinstance(result, dict) or type(result.get("message_id")) is not int:
            raise TelegramError("Telegram returned an invalid receipt message.")
        return not cancel.is_set()
