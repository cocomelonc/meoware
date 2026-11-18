import os
import shutil
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from linux.core import ROOT
from linux.gui import Application
from tools.corpus.storage import verify


@unittest.skipUnless(os.environ.get("MEOWARE_GUI_TESTS") == "1", "Enable MEOWARE_GUI_TESTS=1 on an X11 desktop.")
class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = Application(self.root, interactive_errors=False)
        self.directories = [self.app.lab.directory]
        self.root.update()

    def tearDown(self):
        self.wait(lambda: not self.app.busy)
        self.app.closed = True
        self.app.cancel.set()
        self.app.engine.shutdown(wait=True)
        self.app.network.shutdown(wait=True)
        self.app.lab.close()
        self.root.destroy()
        for directory in self.directories:
            shutil.rmtree(directory, ignore_errors=True)

    def wait(self, condition, timeout=15):
        end = time.monotonic() + timeout
        while not condition():
            self.root.update()
            if time.monotonic() > end:
                self.fail("The desktop operation did not finish within the timeout.")
            time.sleep(0.01)
        self.root.update()

    def load_and_encrypt(self):
        self.app.buttons["load_demo"].invoke()
        self.wait(lambda: not self.app.busy)
        self.assertEqual(len(list(self.app.lab.directory.rglob("*.txt"))), 6)
        self.app.buttons["run"].invoke()
        self.wait(lambda: not self.app.busy)
        self.assertEqual(self.app.state, 1)

    def test_real_widgets_load_encrypt_tamper_retry_restore_and_new_session(self):
        self.load_and_encrypt()
        self.assertEqual(str(self.app.picker.cget("state")), "disabled")
        self.assertEqual(str(self.app.buttons["restore"].cget("state")), "normal")
        record = next(self.app.lab.directory.rglob("*.meoware"))
        original = record.read_bytes()
        changed = bytearray(original)
        changed[-1] ^= 1
        record.write_bytes(changed)
        self.app.buttons["restore"].invoke()
        self.wait(lambda: not self.app.busy)
        self.assertEqual(self.app.state, 1)
        self.assertIn("authentication", self.app.journal.get("1.0", "end"))
        record.write_bytes(original)
        self.app.buttons["restore"].invoke()
        self.wait(lambda: not self.app.busy)
        self.assertEqual(self.app.state, 2)
        verify(ROOT / "datasets/corpora/smoke-42", self.app.lab.directory)
        old = self.app.lab.directory
        self.app.buttons["new"].invoke()
        self.directories.append(self.app.lab.directory)
        self.assertEqual(self.app.state, 0)
        self.assertNotEqual(self.app.lab.directory, old)
        self.assertTrue(old.is_dir())

    def test_gui_deadline_uses_only_the_active_session_manifest(self):
        self.load_and_encrypt()
        extra = self.app.lab.directory / "after-encryption.txt"
        extra.write_text("not part of the session")
        self.app.deadline = time.monotonic() - 1
        self.wait(lambda: self.app.state == 3)
        self.assertEqual(extra.read_text(), "not part of the session")
        self.assertFalse(list(self.app.lab.directory.rglob("*.meoware")))
        self.assertEqual(str(self.app.buttons["restore"].cget("state")), "disabled")

    def test_gui_mock_telegram_approval_restores_and_verifies_corpus(self):
        self.load_and_encrypt()

        class MockBot:
            def __init__(self, token):
                self.reference = None

            def call(self, method, payload, photo=None):
                if method == "getWebhookInfo": return {"url": ""}
                if method == "sendPhoto":
                    if "DEMO PAYMENT" in payload["caption"]:
                        self.reference = payload["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
                        return {"message_id": 77}
                    return {"message_id": 78}
                if method == "getUpdates":
                    return [{"update_id": 1, "callback_query": {
                        "id": "query_test", "from": {"id": 42},
                        "message": {"message_id": 77, "chat": {"id": 42, "type": "private"}},
                        "data": self.reference}}]
                return True

        with patch("linux.gui.configuration", return_value=("123:test", 42)), patch("linux.gui.BotAPI", MockBot):
            self.app.buttons["transfer"].invoke()
            self.wait(lambda: self.app.state == 2)
        self.assertTrue(self.app.receipt.startswith("MEOWARE-DEMO-"))
        verify(ROOT / "datasets/corpora/smoke-42", self.app.lab.directory)


if __name__ == "__main__":
    unittest.main()
