from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from linux.core import Lab
from linux.telegram import ApprovalFlow, TelegramError, configuration


class FakeAPI:
    def __init__(self, callback=None, webhook="", cancel=None, fail_receipt=False):
        self.calls = []
        self.callback = callback
        self.webhook = webhook
        self.cancel = cancel
        self.fail_receipt = fail_receipt

    def call(self, method, payload, photo=None):
        self.calls.append((method, deepcopy(payload), photo))
        if method == "getWebhookInfo":
            return {"url": self.webhook}
        if method == "sendPhoto":
            receipt = "DEMO RECEIPT" in payload["caption"]
            if receipt and self.fail_receipt:
                raise TelegramError("simulated receipt failure")
            return {"message_id": 78 if receipt else 77}
        if method == "getUpdates":
            if self.callback is None:
                if self.cancel:
                    self.cancel.set()
                return []
            return [{"update_id": 42, "callback_query": self.callback}]
        return True


def callback(reference="a" * 32):
    return {"id": "query_123", "from": {"id": 42},
            "message": {"message_id": 77, "chat": {"id": 42, "type": "private"}},
            "data": "meow:" + reference}


class TelegramTests(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()
        self.cancel = threading.Event()

    def tearDown(self):
        directory = self.lab.directory
        self.lab.close()
        shutil.rmtree(directory)

    def test_shared_c_approval_validation_rejects_wrong_identity_or_reference(self):
        good = callback()
        self.assertEqual(self.lab.approved(good, 42, 77, "a" * 32), "query_123")
        changes = [("sender", 99), ("chat", 99), ("message", 99), ("type", "group"),
                   ("data", "meow:" + "b" * 32), ("query", 'bad"query')]
        for field, value in changes:
            bad = deepcopy(good)
            if field == "sender": bad["from"]["id"] = value
            elif field == "chat": bad["message"]["chat"]["id"] = value
            elif field == "message": bad["message"]["message_id"] = value
            elif field == "type": bad["message"]["chat"]["type"] = value
            elif field == "data": bad["data"] = value
            else: bad["id"] = value
            self.assertIsNone(self.lab.approved(bad, 42, 77, "a" * 32), field)

    def test_complete_mock_flow_and_payload_minimization(self):
        api, events = FakeAPI(callback()), []
        flow = ApprovalFlow(self.lab, api, 42, "a" * 32, b"public-cat-image")
        self.assertTrue(flow.run(self.cancel, lambda *e: events.append(e)))
        self.assertEqual(flow.receipt, "MEOWARE-DEMO-" + "a" * 32)
        photos = [p for m, p, image in api.calls if m == "sendPhoto"]
        self.assertEqual(len(photos), 2)
        self.assertIn("25 meowcoins", photos[0]["caption"])
        self.assertIn("No real payment", photos[1]["caption"])
        self.assertEqual(len(events), 1)
        text = json.dumps([(m, p) for m, p, image in api.calls])
        for secret in [str(self.lab.directory), "mac_key", "portable_key", "payload/"]:
            self.assertNotIn(secret, text)

    def test_cancellation_never_emits_approval_or_receipt(self):
        api = FakeAPI(cancel=self.cancel)
        flow = ApprovalFlow(self.lab, api, 42, "a" * 32, b"cat")
        self.assertFalse(flow.run(self.cancel, lambda *e: None))
        self.assertIsNone(flow.receipt)
        self.assertEqual(sum(m == "sendPhoto" for m, p, photo in api.calls), 1)

    def test_webhook_refusal_does_not_delete_webhook_or_send_photo(self):
        api = FakeAPI(webhook="https://configured.example/hook")
        with self.assertRaises(TelegramError):
            ApprovalFlow(self.lab, api, 42, "a" * 32, b"cat").run(self.cancel, lambda *e: None)
        self.assertEqual([m for m, p, photo in api.calls], ["getWebhookInfo"])

    def test_failed_receipt_never_reports_success(self):
        api = FakeAPI(callback(), fail_receipt=True)
        with self.assertRaises(TelegramError):
            ApprovalFlow(self.lab, api, 42, "a" * 32, b"cat").run(self.cancel, lambda *e: None)
        self.assertEqual(self.lab.state, 0)

    def test_invalid_configuration_has_no_secret_in_error(self):
        with tempfile.TemporaryDirectory(prefix="meoware-bot-config-test-") as d:
            path = Path(d) / "config.json"
            for value in [{"token": "secret-never-print", "chat_id": 42},
                          {"token": "123:valid_demo", "chat_id": True},
                          {"token": "123:valid_demo", "chat_id": -42}]:
                path.write_text(json.dumps(value))
                with self.assertRaises(TelegramError) as error:
                    configuration(path)
                self.assertNotIn(value["token"], str(error.exception))
            path.write_text(json.dumps({"token": "123:valid_demo", "chat_id": 42}))
            self.assertEqual(configuration(path), ("123:valid_demo", 42))


if __name__ == "__main__":
    unittest.main()
