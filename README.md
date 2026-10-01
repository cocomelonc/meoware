# Meoware EDU

Meoware EDU is a standalone C/Win32 ransomware simulation PoC for different cryptographic algorithms. The GUI creates a unique temporary folder with five bundled sample files, encrypts those files with the selected algorithm (AES or TEA), shows a 24-hour countdown, and restores the samples while the session key is in memory. If the countdown expires, the deadline branch removes only the five encrypted sample outputs from that lab.

![img](./screenshots/1.png)    

The lab directory is created under the current user's Windows temporary directory. The application does not accept arbitrary target paths or enumerate drives. It makes no network requests, does not register file associations, and does not touch the registry. The payment scenario uses fictional meowcoins and an in-memory receipt; no real payment is requested or verified.

The sample text assets are embedded into the executable at build time, so the GUI no longer depends on an `assets/` folder beside the binary. The C implementation separates the Win32 UI, lab workflow, cipher dispatch, and portable TEA and receipt modules. AES and random key/IV generation use Windows CNG.

## Algorithms

Choose an algorithm in the `ALGORITHM` list before clicking `Run demo`. AES is the default. The selection locks when the session starts; direct restoration and mock-payment restoration both use that session's cipher and key. Restart the application to try another algorithm in a fresh lab.

| GUI option | Key | Block / IV | Implementation |
| --- | --- | --- | --- |
| AES-256-CBC | 256 bits | 128 bits | Windows CNG |
| TEA-128-CBC | 128 bits | 64 bits | Classic TEA, 32 cycles (64 half-rounds), explicit big-endian words |

Both modes use PKCS#7 padding, a fresh random session key, and a fresh IV per sample. This is a teaching lab: the CBC records do not provide authenticated encryption.

The algorithm selection follows the cryptography series in [cocomelonc's blog](https://cocomelonc.github.io/malware/2023/02/20/malware-av-evasion-12.html). The C snippet in that article uses XTEA-style mixing despite its TEA function names. This implementation follows [Wheeler and Needham's original TEA specification](https://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html), with known-answer tests from [Crypto++'s TEA vectors](https://github.com/weidai11/cryptopp/blob/master/TestVectors/tea.txt). Other algorithms will be added separately.

The algorithm catalog in `src/crypto.c` supplies the GUI names, IDs, and sizes. Additional ciphers can extend this catalog and dispatch without changing the payment scenario. New `.meoware` records use a 24-byte header: `MWA2`, a one-byte algorithm ID, a one-byte IV length, two reserved zero bytes, and a 16-byte IV slot (zero-filled after a shorter IV). Ciphertext follows the header. Restoration rejects mismatched cipher IDs or IV lengths. The old `MWA1` format is not read by this version; keys remain in process memory and there is no cross-session restore feature.

## build with MinGW-w64

From this directory:    

```bash
make
```

Or invoke the compiler directly:    

```bash
x86_64-w64-mingw32-windres -i src/assets.rc -O coff -o meoware-assets.o
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Wpedantic \
  -Iinclude -mwindows -o meoware.exe \
  src/main.c src/lab.c src/crypto.c src/tea.c src/receipt.c meoware-assets.o \
  -lbcrypt -luser32 -lgdi32
```

![img](./screenshots/2.png)     

The build does not require Visual Studio or MFC. The sample assets are packed into `meoware.exe`; no sidecar data directory is required at runtime.    

## Ransomware lab behavior

`Run demo` replaces only the five sample copies inside the unique `CryptPath` folder with `.meoware` outputs. `Restore samples` decrypts them with the key held by the current process. The deadline branch removes only those generated encrypted outputs. The lab directory is left in the temp folder so its contents can be inspected.     

## Payment simulation

1. Click `Run demo` to start the lab and open a fictional receipt for 25 meowcoins.
2. Click `Simulate transfer`. The receipt progresses through three local confirmations, one every two seconds.
3. Click `Check receipt` after `3/3` confirmations to restore the five samples. Checking earlier explains whether the transfer is missing or still pending.

`Show activity` switches the right-hand card to the session log; `Payment demo` switches back. `Restore samples` remains available throughout the active lab, independently of the mock receipt. Restoration, expiry, or an operation error closes the receipt and disables further transfers. Duplicate submissions do not add meowcoins or restart confirmation progress.

The displayed `demo://meoware/local-session` destination is a fictional label, not a wallet or a link. Receipts exist only for the current process. The payment module is an original C implementation with its own state model, UI text, and identifiers; it does not import the reference project's payment or wallet code.

Run the portable receipt and TEA tests with a host C compiler (no Windows or Wine needed). These cover published TEA vectors, CBC chaining, padding rejection, buffer boundaries, in-place operations, and exact restoration of the five bundled samples:

```bash
make test
```

Build the Windows integration tests with `make windows-test-build`. Run the resulting `/tmp/meoware-lab-tests.exe` on Windows or under Wine to check both AES and TEA through the actual lab workflow, including header validation, restoration against embedded resources, and the deadline branch. The tests create their own temporary labs and remove them after successful checks.
