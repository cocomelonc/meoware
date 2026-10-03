# meowcoins GUI approval flow

Python is not required. The GUI uses WinHTTP to call Telegram's
Bot API directly and is the only update consumer for this bot token.

1. Put `token` and your positive private `chat_id` in `bot/config.json`.
2. Run `make`. The test credentials and cat photo are embedded in `meoware.exe`.
   Rebuild whenever the configuration changes. This test EXE contains the token.
3. Stop other clients and GUI instances using the same token.
   Open the bot in your Telegram account and send `/start` if you have not done so.
4. Run the new EXE on Windows, click **Run demo**, then **Simulate transfer**.
5. In your Telegram chat, press **Payment: OK - send receipt** on the new photo.
6. The GUI validates the operator, private chat, message, and random session
   reference. It sends a cat photo with the demo receipt to your chat, displays
   the receipt in the GUI, and restores the five generated sample files.

The GUI stays responsive while waiting. **Check receipt** shows its status and,
after approval, the receipt. **Restore samples** always allows local recovery.
Network errors expose **Retry transfer**; each retry creates a new reference.
Only the current request can approve restoration. An existing webhook or
competing poller produces a setup error; the GUI does not remove webhooks.

Only the fictional amount, random reference, and fixed demo text are sent.
No encryption keys, sample contents, paths, or machine information are sent.
The receipt is an operator-approved simulation, not evidence of payment.

Run `make test` for the cipher and Telegram approval tests; `make windows-test-build` compiles the Windows lab checks.
