"""Small ctypes bridge to the shared C cipher and Linux lab implementation."""

import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "linux/build/libmeoware.so"


class LabError(RuntimeError):
    pass


class CipherInfo(C.Structure):
    _fields_ = [("id", C.c_int), ("name", C.c_char_p), ("key_size", C.c_uint),
                ("block_size", C.c_uint), ("iv_size", C.c_uint)]


class Json(C.Structure):
    _fields_ = [("text", C.c_char_p), ("size", C.c_size_t)]


def library():
    if not LIBRARY.is_file():
        raise LabError("Build linux/build/libmeoware.so first; see linux/README.md.")
    lib = C.CDLL(str(LIBRARY))
    lib.linux_lab_new.argtypes = [C.c_char_p, C.c_size_t]
    lib.linux_lab_new.restype = C.c_void_p
    lib.linux_lab_free.argtypes = [C.c_void_p]
    lib.linux_lab_free.restype = None
    lib.linux_lab_directory.argtypes = [C.c_void_p]
    lib.linux_lab_directory.restype = C.c_char_p
    for name, result in [("state", C.c_int), ("file_count", C.c_size_t), ("bytes", C.c_uint64)]:
        fn = getattr(lib, "linux_lab_" + name)
        fn.argtypes = [C.c_void_p]
        fn.restype = result
    lib.linux_lab_encrypt.argtypes = [C.c_void_p, C.c_uint, C.c_char_p, C.c_size_t]
    lib.linux_lab_encrypt.restype = C.c_int
    for name in ["restore", "expire"]:
        fn = getattr(lib, "linux_lab_" + name)
        fn.argtypes = [C.c_void_p, C.c_char_p, C.c_size_t]
        fn.restype = C.c_int
    lib.crypto_algorithm_count.restype = C.c_size_t
    lib.crypto_algorithm_at.argtypes = [C.c_size_t]
    lib.crypto_algorithm_at.restype = C.POINTER(CipherInfo)
    lib.approval_matches.argtypes = [Json, C.c_int64, C.c_int64, C.c_char_p, C.c_char_p]
    lib.approval_matches.restype = C.c_bool
    return lib


class Lab:
    def __init__(self):
        self.lib = library()
        error = C.create_string_buffer(512)
        self.handle = self.lib.linux_lab_new(error, len(error))
        if not self.handle:
            raise LabError(error.value.decode("utf-8", "replace"))
        self.directory = Path(os.fsdecode(self.lib.linux_lab_directory(self.handle)))
        self.algorithms = []
        for i in range(self.lib.crypto_algorithm_count()):
            info = self.lib.crypto_algorithm_at(i).contents
            self.algorithms.append({"id": info.id, "name": info.name.decode(),
                                    "key_bits": info.key_size * 8, "block_bytes": info.block_size,
                                    "iv_bytes": info.iv_size})

    @property
    def state(self):
        return self.lib.linux_lab_state(self.handle)

    @property
    def count(self):
        return self.lib.linux_lab_file_count(self.handle)

    @property
    def size(self):
        return self.lib.linux_lab_bytes(self.handle)

    def _operation(self, name, *arguments):
        if not self.handle:
            raise LabError("This lab session is closed.")
        error = C.create_string_buffer(512)
        if not getattr(self.lib, "linux_lab_" + name)(self.handle, *arguments, error, len(error)):
            raise LabError(error.value.decode("utf-8", "replace") or "The lab operation failed.")

    def encrypt(self, algorithm):
        self._operation("encrypt", algorithm)

    def restore(self):
        self._operation("restore")

    def expire(self):
        self._operation("expire")

    def approved(self, callback, chat_id, message_id, reference):
        encoded = json.dumps(callback, ensure_ascii=True, separators=(",", ":")).encode()
        query = C.create_string_buffer(128)
        if self.lib.approval_matches(Json(encoded, len(encoded)), chat_id, message_id,
                                     reference.encode("ascii"), query):
            return query.value.decode("ascii")
        return None

    def close(self):
        if self.handle:
            self.lib.linux_lab_free(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()

    def import_corpus(self, corpus):
        """Verify the shared generator's manifest, then copy fixtures into this lab."""
        from tools.corpus.storage import verify
        from tools.corpus.model import relative_path

        if self.state != 0 or any(self.directory.iterdir()):
            raise LabError("Import requires a fresh, empty lab session.")
        corpus = Path(corpus).resolve()
        verify(corpus)
        manifest = json.loads((corpus / "manifest.json").read_text())
        if manifest["payload_bytes"] > 256 * 1024 * 1024:
            raise LabError("The Linux lab accepts up to 256 MiB per session.")
        count = 0
        created = []
        try:
            with (corpus / "files.jsonl").open() as index:
                for line in index:
                    row = json.loads(line)
                    name = row["relative_path"]
                    relative_path(name)
                    source = corpus / "payload" / name
                    destination = self.directory / name
                    for parent in source.parents:
                        if parent == corpus:
                            break
                        if parent.is_symlink():
                            raise LabError("Corpus paths must not contain symbolic links.")
                    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, "rb") as incoming:
                        info = os.fstat(incoming.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise LabError("Corpus payload must contain separate regular files.")
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        digest, size = hashlib.sha256(), 0
                        with destination.open("xb") as output:
                            created.append(destination)
                            while data := incoming.read(65536):
                                size += len(data)
                                if size > row["size_bytes"]:
                                    raise LabError("Corpus file changed during import.")
                                digest.update(data)
                                output.write(data)
                        if size != row["size_bytes"] or digest.hexdigest() != row["sha256"]:
                            raise LabError("Corpus file changed during import.")
                    count += 1
            return {"files": count, "bytes": manifest["payload_bytes"], "corpus_id": manifest["corpus_id"]}
        except Exception:
            for p in created:
                p.unlink(missing_ok=True)
            for p in sorted(self.directory.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                if p.is_dir() and not p.is_symlink():
                    try:
                        p.rmdir()
                    except OSError:
                        pass
            raise
