"""Linux desktop interface; file processing remains in the shared C library."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import queue
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .core import Lab, LabError, ROOT
from .telegram import ApprovalFlow, BotAPI, TelegramError, configuration

BG = "#f7f5fa"
PANEL = "#fffefe"
INK = "#393146"
MUTED = "#70667c"
ACCENT = "#775b9e"
SOFT = "#efe9f7"
TEAL = "#347462"
ROSE = "#a4465e"


class Application:
    def __init__(self, root, interactive_errors=True):
        self.root = root
        self.interactive_errors = interactive_errors
        self.lab = Lab()
        self.engine = ThreadPoolExecutor(max_workers=1, thread_name_prefix="meoware-core")
        self.network = ThreadPoolExecutor(max_workers=1, thread_name_prefix="meoware-telegram")
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.generation = 0
        self.busy = False
        self.bot_running = False
        self.closed = False
        self.deadline = None
        self.receipt = None
        self.corpus = None
        self.state = 0
        self.buttons = {}
        self._build()
        self.log("Private Linux lab created. Load a generated corpus to begin.")
        self._refresh()
        self.root.after(80, self._poll)
        self.root.after(200, self._tick)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def label(self, parent, text="", size=10, color=INK, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("DejaVu Sans", size, "bold" if bold else "normal"), **kwargs)

    def button(self, parent, key, text, command, primary=False):
        b = tk.Button(parent, text=text, command=command, bg=ACCENT if primary else SOFT,
                      fg="white" if primary else INK, activebackground="#684b90" if primary else "#e5dbee",
                      activeforeground="white" if primary else INK, relief="flat", bd=0,
                      padx=15, pady=10, font=("DejaVu Sans", 10, "bold"), cursor="hand2",
                      disabledforeground="#b1a8ba", highlightthickness=0)
        self.buttons[key] = b
        return b

    def card(self, parent, **kwargs):
        return tk.Frame(parent, bg=PANEL, padx=20, pady=17, highlightbackground="#e3dcec",
                        highlightthickness=1, **kwargs)

    def _build(self):
        self.root.title("Meoware EDU · Linux")
        self.root.configure(bg=BG)
        self.root.geometry("1120x840")
        self.root.minsize(1020, 790)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground=PANEL, background=SOFT, foreground=INK,
                        arrowcolor=ACCENT, bordercolor="#e3dcec", padding=8)
        style.map("TCombobox", fieldbackground=[("readonly", PANEL)], selectbackground=[("readonly", PANEL)],
                  selectforeground=[("readonly", INK)])
        style.configure("Lab.Horizontal.TProgressbar", background=ACCENT, troughcolor=SOFT,
                        bordercolor=SOFT, lightcolor=ACCENT, darkcolor=ACCENT)

        header = tk.Frame(self.root, bg=BG, padx=28, pady=18)
        header.pack(fill="x")
        title = tk.Frame(header, bg=BG)
        title.pack(side="left")
        self.label(title, "meoware", 29, bold=True).pack(anchor="w")
        self.label(title, "A SMALL LAB. A COMPLETE CRYPTO STORY.", 9, color=ACCENT).pack(anchor="w", pady=(2, 0))
        badge = tk.Label(header, text="LINUX  /  LOCAL C CORE", bg=SOFT, fg=ACCENT,
                         padx=13, pady=9, font=("DejaVu Sans Mono", 9, "bold"))
        badge.pack(side="right", anchor="n", pady=10)

        body = tk.Frame(self.root, bg=BG, padx=28)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)
        left = self.card(body, width=285)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 18))
        left.grid_propagate(False)
        self.label(left, "YOUR CRYPTO LAB", 10, color=ACCENT, bold=True).pack(anchor="w")
        picture = tk.PhotoImage(file=str(ROOT / "screenshots/meoware-kitten.png"))
        self.cat = picture.subsample(5, 5)
        self.root.iconphoto(True, self.cat)
        tk.Label(left, image=self.cat, bg=PANEL).pack(pady=(0, 0))
        self.label(left, "Curious paws. Exact bytes.", 11, bold=True).pack()
        self.label(left, "Generate · encrypt · inspect · restore", 8, color=MUTED).pack(pady=(5, 20))
        self.button(left, "load_demo", "Load demo corpus", self.load_demo, True).pack(fill="x", pady=(0, 8))
        self.button(left, "load", "Choose corpus…", self.choose_corpus).pack(fill="x", pady=(0, 8))
        self.button(left, "open", "Open lab folder", self.open_folder).pack(fill="x", pady=(0, 8))
        self.button(left, "new", "New session", self.new_session).pack(fill="x")
        self.label(left, "Disposable corpus only.\nRecovery keys stay in this session.", 9,
                   color=MUTED, justify="left", wraplength=240).pack(anchor="w", pady=(20, 0))

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        profile = self.card(right)
        profile.pack(fill="x", pady=(0, 12))
        self.status = self.label(profile, "READY TO EXPLORE", 10, color=TEAL, bold=True)
        self.status.pack(anchor="w")
        self.label(profile, "Choose your cipher", 18, bold=True).pack(anchor="w", pady=(7, 10))
        self.algorithm = tk.StringVar(value=self.lab.algorithms[0]["name"])
        self.picker = ttk.Combobox(profile, textvariable=self.algorithm, state="readonly",
                                   values=[a["name"] for a in self.lab.algorithms], font=("DejaVu Sans", 11))
        self.picker.pack(fill="x")
        self.picker.bind("<<ComboboxSelected>>", lambda event: self._algorithm_info())
        self.crypto_details = self.label(profile, size=9, color=MUTED)
        self.crypto_details.pack(anchor="w", pady=(9, 0))
        self._algorithm_info()

        scenario = self.card(right)
        scenario.pack(fill="x", pady=(0, 12))
        top = tk.Frame(scenario, bg=PANEL)
        top.pack(fill="x")
        clock = tk.Frame(top, bg=PANEL)
        clock.pack(side="left")
        self.label(clock, "SESSION COUNTDOWN", 9, color=MUTED, bold=True).pack(anchor="w")
        self.timer = tk.Label(clock, text="24:00:00", bg=PANEL, fg=INK,
                              font=("DejaVu Sans Mono", 28, "bold"))
        self.timer.pack(anchor="w", pady=(4, 0))
        receipt = tk.Frame(top, bg=PANEL)
        receipt.pack(side="right", padx=(15, 0))
        self.label(receipt, "DEMO REQUEST", 9, color=MUTED, bold=True).pack(anchor="w")
        self.label(receipt, "25 meowcoins", 18, color=ACCENT, bold=True).pack(anchor="w", pady=(8, 0))
        self.label(receipt, "Fictional coins · operator approval", 8, color=MUTED).pack(anchor="w", pady=(5, 0))
        controls = tk.Frame(scenario, bg=PANEL)
        controls.pack(fill="x", pady=(16, 0))
        self.button(controls, "run", "Run demo", self.run_demo, True).pack(side="left", padx=(0, 9))
        self.button(controls, "restore", "Restore lab", self.restore).pack(side="left", padx=(0, 9))
        self.button(controls, "transfer", "Simulate transfer", self.transfer).pack(side="left")
        self.payment = self.label(scenario, "Local restore works independently of Telegram.", 9, color=MUTED,
                                   anchor="w", justify="left", wraplength=660)
        self.payment.pack(fill="x", pady=(12, 0))
        self.button(scenario, "receipt", "Check receipt", self.check_receipt).pack(anchor="w", pady=(9, 0))

        evidence = self.card(right)
        evidence.pack(fill="both", expand=True)
        self.summary = self.label(evidence, "SESSION JOURNAL", 9, color=MUTED, bold=True)
        self.summary.pack(anchor="w")
        self.progress = ttk.Progressbar(evidence, style="Lab.Horizontal.TProgressbar", mode="indeterminate")
        self.progress.pack(fill="x", pady=(10, 10))
        self.journal = tk.Text(evidence, height=5, bg=PANEL, fg=INK, font=("DejaVu Sans Mono", 9),
                               relief="flat", bd=0, wrap="word", state="disabled", highlightthickness=0)
        self.journal.pack(fill="both", expand=True)

        bottom = tk.Frame(self.root, bg=BG, padx=28, pady=15)
        bottom.pack(fill="x")
        self.path = self.label(bottom, str(self.lab.directory), 9, color=ACCENT)
        self.path.pack(side="left")
        self.label(bottom, "MWA3 · HMAC-SHA-256 · 64 KiB streaming", 8, color=MUTED).pack(side="right")

    def _algorithm_info(self):
        a = next(a for a in self.lab.algorithms if a["name"] == self.algorithm.get())
        mode = f'{a["block_bytes"] * 8}-bit block · PKCS#7' if a["block_bytes"] else "continuous stream · no padding"
        self.crypto_details.configure(text=f'{a["key_bits"]}-bit key   /   {mode}   /   per-file IV')

    def log(self, text):
        self.journal.configure(state="normal")
        self.journal.insert("end", datetime.now().strftime("%H:%M:%S") + "  " + text + "\n")
        if int(self.journal.index("end-1c").split(".")[0]) > 100:
            self.journal.delete("1.0", "2.0")
        self.journal.see("end")
        self.journal.configure(state="disabled")

    def _refresh(self):
        labels = {0: ("READY TO EXPLORE", TEAL), 1: ("ENCRYPTED · SESSION KEYS IN MEMORY", ROSE),
                  2: ("RESTORED · READY FOR VERIFICATION", TEAL), 3: ("DEADLINE REACHED · SESSION EXPIRED", ROSE)}
        text, color = labels[self.state]
        self.status.configure(text="WORKING…" if self.busy else text, fg=color)
        self.picker.configure(state="disabled" if self.busy or self.state != 0 else "readonly")
        allowed = {"run": self.state == 0, "load": self.state == 0 and self.corpus is None,
                   "load_demo": self.state == 0 and self.corpus is None,
                   "restore": self.state == 1, "transfer": self.state == 1 and not self.bot_running,
                   "new": self.state != 1, "receipt": bool(self.receipt) or self.bot_running,
                   "open": True}
        for key, button in self.buttons.items():
            button.configure(state="normal" if allowed[key] and not self.busy else "disabled")
        if self.busy:
            self.progress.start(15)
        else:
            self.progress.stop()
            self.progress.configure(value=0)

    def _submit(self, function, done):
        if self.busy:
            return
        self.busy = True
        self._refresh()
        future = self.engine.submit(function)
        generation = self.generation
        def completed(f):
            try:
                value = (True, f.result())
            except Exception as e:
                value = (False, str(e))
            self.events.put(("core", generation, (done, value)))
        future.add_done_callback(completed)

    def _error(self, message):
        self.log(message)
        if self.interactive_errors:
            messagebox.showerror("Meoware lab", message, parent=self.root)

    def load_demo(self):
        corpus = ROOT / "datasets/corpora/smoke-42"
        if not corpus.is_dir():
            self._error("Generate the smoke-42 corpus first; see linux/README.md.")
            return
        self.load_corpus(corpus)

    def choose_corpus(self):
        path = filedialog.askdirectory(parent=self.root, title="Choose a generated corpus with manifest.json",
                                       initialdir=str(ROOT / "datasets/corpora"))
        if path:
            self.load_corpus(Path(path))

    def load_corpus(self, path):
        def done(result):
            self.corpus = Path(path).resolve()
            self.summary.configure(text=f'{result["files"]} FILES  /  {result["bytes"]:,} BYTES  /  CORPUS {result["corpus_id"][:12]}')
            self.log("Verified corpus copied into the private lab folder.")
        self._submit(lambda: self.lab.import_corpus(path), done)

    def open_folder(self):
        try:
            subprocess.Popen(["xdg-open", str(self.lab.directory)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            self._error("Open the private path displayed at the bottom of the window.")

    def run_demo(self):
        algorithm = next(a for a in self.lab.algorithms if a["name"] == self.algorithm.get())
        def done(result):
            self.deadline = time.monotonic() + 86400
            self.log(f'{algorithm["name"]}: {self.lab.count} files staged, authenticated and committed.')
            self.log("Restore locally or request the fictional meowcoins receipt.")
        self._submit(lambda: self.lab.encrypt(algorithm["id"]), done)

    def restore(self):
        if self.busy or self.state != 1:
            return
        self.cancel.set()
        self.generation += 1
        self.bot_running = False
        def done(result):
            self.deadline = None
            self.timer.configure(text="RESTORED", fg=TEAL, font=("DejaVu Sans Mono", 23, "bold"))
            self.log("Authentication passed. Original bytes, paths, modes and times restored.")
            self.log("Verify the recovered payload against its original corpus manifest.")
        self._submit(self.lab.restore, done)

    def new_session(self):
        if self.busy or self.state == 1:
            return
        self.cancel.set()
        self.generation += 1
        self.lab.close()
        self.lab = Lab()
        self.cancel = threading.Event()
        self.state = 0
        self.bot_running = False
        self.receipt = self.corpus = self.deadline = None
        self.path.configure(text=str(self.lab.directory))
        self.timer.configure(text="24:00:00", fg=INK, font=("DejaVu Sans Mono", 28, "bold"))
        self.summary.configure(text="SESSION JOURNAL")
        self.payment.configure(text="Local restore works independently of Telegram.")
        self.buttons["transfer"].configure(text="Simulate transfer")
        self.log("New private lab created; the previous folder remains available for inspection.")
        self._refresh()

    def transfer(self):
        if self.busy or self.state != 1 or self.bot_running:
            return
        try:
            token, chat_id = configuration()
            flow = ApprovalFlow(self.lab, BotAPI(token), chat_id)
        except TelegramError as e:
            self._error(str(e))
            return
        self.cancel = threading.Event()
        cancel, generation = self.cancel, self.generation
        self.bot_running = True
        self.payment.configure(text="Sending a fictional meowcoins request…")
        self._refresh()
        def worker():
            try:
                ok = flow.run(cancel, lambda state, text: self.events.put(("waiting", generation, text)))
                self.events.put(("approved" if ok else "cancelled", generation, flow.receipt))
            except Exception as e:
                self.events.put(("network_error", generation, str(e)))
        self.network.submit(worker)

    def check_receipt(self):
        text = ("Receipt: " + self.receipt + "\n25 fictional meowcoins\nApproved by the lab operator.") if self.receipt else "Waiting for approval in the configured private Telegram chat."
        if self.interactive_errors:
            messagebox.showinfo("Meowcoins demo receipt", text, parent=self.root)

    def _poll(self):
        if self.closed:
            return
        while True:
            try:
                kind, generation, value = self.events.get_nowait()
            except queue.Empty:
                break
            if generation != self.generation:
                continue
            if kind == "core":
                done, (ok, result) = value
                self.busy = False
                self.state = self.lab.state
                if ok:
                    done(result)
                else:
                    if self.state == 1 and self.deadline is None:
                        self.deadline = time.monotonic() + 86400
                    self._error(result)
                self._refresh()
            elif kind == "waiting":
                self.payment.configure(text=value)
                self.log(value)
            elif kind == "approved":
                self.bot_running = False
                if self.state == 1 and not self.cancel.is_set():
                    self.receipt = value
                    self.payment.configure(text="Operator approved · receipt sent · restoring the lab.")
                    self.log("Meowcoins receipt accepted for this session.")
                    self.restore()
            elif kind in ("network_error", "cancelled"):
                self.bot_running = False
                if kind == "network_error":
                    self.payment.configure(text="Transfer failed. Retry or restore locally.")
                    self.buttons["transfer"].configure(text="Retry transfer")
                    self.log(value)
                self._refresh()
        self.root.after(80, self._poll)

    def _tick(self):
        if self.closed:
            return
        if self.deadline is not None and self.state == 1:
            remaining = max(0, int(self.deadline - time.monotonic()))
            self.timer.configure(text=f"{remaining // 3600:02d}:{remaining // 60 % 60:02d}:{remaining % 60:02d}")
            if remaining == 0 and not self.busy:
                self.cancel.set()
                self.generation += 1
                self.bot_running = False
                def done(result):
                    self.deadline = None
                    self.log("Deadline reached. Only this session's encrypted records were removed.")
                self._submit(self.lab.expire, done)
        self.root.after(200, self._tick)

    def close(self):
        if self.busy:
            if self.interactive_errors:
                messagebox.showinfo("Meoware lab", "Wait for the current operation before closing.", parent=self.root)
            return
        if self.state == 1:
            if self.interactive_errors and messagebox.askyesno("Restore before closing?",
                    "Session keys will be lost on exit. Restore the lab before closing?", parent=self.root):
                self.restore()
                return
            if not self.interactive_errors:
                return
        self.closed = True
        self.cancel.set()
        self.engine.shutdown(wait=False)
        self.network.shutdown(wait=False)
        self.lab.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        Application(root)
        root.mainloop()
    except LabError as e:
        root.withdraw()
        messagebox.showerror("Meoware Linux", str(e), parent=root)
        root.destroy()


if __name__ == "__main__":
    main()
