# Meoware EDU

Meoware EDU is a standalone C/Win32 ransomware simulation educational lab. The GUI creates a unique temporary folder with five bundled sample files, encrypts those files with AES-256-CBC, shows a 24-hour countdown, and restores the samples while the session key is in memory. If the countdown expires, the deadline branch removes only the five encrypted sample outputs from that lab.

The lab directory is created under the current user's Windows temporary directory. The application does not accept arbitrary target paths or enumerate drives. It makes no network requests, does not register file associations, and does not touch the registry. The payment text is educational; no payment is requested or verified.

The sample text assets are embedded into the executable at build time, so the GUI no longer depends on an `assets/` folder beside the binary. The C implementation is structured into a Win32 UI, lab file workflow, and Windows CNG crypto module. AES is provided by the Windows platform, not copied crypto source.

## Build with MinGW-w64

From this directory:

```sh
make
```

Or invoke the compiler directly:

```sh
x86_64-w64-mingw32-windres -i src/assets.rc -O coff -o meoware-assets.o
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Wpedantic \
  -Iinclude -mwindows -o meoware.exe \
  src/main.c src/lab.c src/crypto.c meoware-assets.o \
  -lbcrypt -luser32 -lgdi32
```

The build does not require Visual Studio or MFC. The sample assets are packed into `meoware.exe`; no sidecar data directory is required at runtime.

## Lab behavior

`Run demo` replaces only the five sample copies inside the unique `CryptPath` folder with `.meoware` outputs. `Restore samples` decrypts them with the key held by the current process. The deadline branch removes only those generated encrypted outputs. The lab directory is left in the temp folder so its contents can be inspected.
