import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from linux.core import Lab, LabError, ROOT
from tools.corpus.storage import verify


class LinuxLabTests(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()
        self.directory = self.lab.directory

    def tearDown(self):
        self.lab.close()
        shutil.rmtree(self.directory, ignore_errors=True)

    def write(self, name, content=b"Meow-meow!\n"):
        p = self.directory / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def test_private_root_and_empty_refusal(self):
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        with self.assertRaises(LabError):
            self.lab.encrypt(1)
        self.assertEqual(self.lab.state, 0)

    def test_all_ciphers_same_corpus_and_original_manifest(self):
        corpus = ROOT / "datasets/corpora/smoke-42"
        self.assertTrue(corpus.is_dir(), "Generate the documented smoke-42 corpus before these integration tests.")
        self.lab.close()
        self.directory.rmdir()
        for algorithm in self.lab.algorithms:
            with self.subTest(cipher=algorithm["name"]):
                self.lab = Lab()
                self.directory = self.lab.directory
                result = self.lab.import_corpus(corpus)
                self.lab.encrypt(algorithm["id"])
                self.assertEqual(self.lab.count, result["files"])
                for p in self.directory.rglob("*.meoware"):
                    header = p.read_bytes()[:32]
                    self.assertEqual(header[:4], b"MWA3")
                    self.assertEqual(header[4], algorithm["id"])
                    self.assertEqual(header[5], algorithm["iv_bytes"])
                    self.assertEqual(header[6:8], bytes(2))
                    n = int.from_bytes(header[8:16], "little")
                    block = algorithm["block_bytes"]
                    expected = (n // block + 1) * block if block else n
                    self.assertEqual(p.stat().st_size, 64 + expected)
                self.lab.restore()
                verify(corpus, self.directory)
                self.assertEqual(self.lab.state, 2)
                self.assertFalse(list(self.directory.rglob("*.meoware")))
                self.lab.close()
                shutil.rmtree(self.directory)

    def test_empty_boundary_nested_unicode_and_metadata(self):
        data = {}
        for size in [0, 1, 7, 8, 15, 16, 17, 65535, 65536, 65537, 131089]:
            p = self.write(f"nested/кот-{size}.bin", bytes((i * 31 + 17) % 256 for i in range(size)))
            p.chmod(0o640)
            os.utime(p, ns=(1600000000000000000, 1600000000123456789))
            data[p] = (hashlib.sha256(p.read_bytes()).digest(), p.stat().st_mtime_ns)
        self.lab.encrypt(1)
        self.lab.restore()
        for p, (digest, mtime) in data.items():
            self.assertEqual(hashlib.sha256(p.read_bytes()).digest(), digest)
            self.assertEqual(p.stat().st_mtime_ns, mtime)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o640)

    def test_tampering_prevents_any_new_plaintext_commit(self):
        a, b = self.write("a.txt"), self.write("b.txt", b"second original")
        self.lab.encrypt(1)
        record = self.directory / "b.txt.meoware"
        original = record.read_bytes()
        changed = bytearray(original)
        changed[-1] ^= 255
        record.write_bytes(changed)
        with self.assertRaises(LabError):
            self.lab.restore()
        self.assertFalse(a.exists())
        self.assertFalse(b.exists())
        self.assertFalse(list(self.directory.rglob("*.restore.tmp")))
        record.write_bytes(original)
        self.lab.restore()
        self.assertEqual(b.read_bytes(), b"second original")

    def test_header_ciphertext_and_truncation_rejected_then_retry(self):
        self.write("record.bin", b"a" * 10000)
        self.lab.encrypt(2)
        p = self.directory / "record.bin.meoware"
        original = p.read_bytes()
        variants = []
        for index in [4, 5, 6, 8, 16, 32, len(original)-1]:
            bad = bytearray(original)
            bad[index] ^= 1
            variants.append(bad)
        variants += [original[:-1], original + b"extra"]
        for value in variants:
            p.write_bytes(value)
            with self.assertRaises(LabError):
                self.lab.restore()
            self.assertFalse((self.directory / "record.bin").exists())
        p.write_bytes(original)
        self.lab.restore()

    def test_links_and_special_files_rejected_without_touching_external_file(self):
        with tempfile.TemporaryDirectory(prefix="meoware-external-test-") as outside:
            external = Path(outside) / "untouched.txt"
            external.write_text("unchanged outside the lab")
            link = self.directory / "link"
            for create in [lambda: link.symlink_to(external), lambda: os.link(external, link),
                           lambda: os.mkfifo(link), lambda: link.symlink_to(outside, target_is_directory=True)]:
                create()
                with self.assertRaises(LabError):
                    self.lab.encrypt(1)
                link.unlink()
                self.assertEqual(external.read_text(), "unchanged outside the lab")
            self.write("normal.txt")
            self.lab.encrypt(1)
            self.lab.restore()

    def test_output_collision_and_invalid_algorithm_preserve_sources(self):
        p = self.write("source.txt")
        collision = self.write("source.txt.meoware", b"existing output")
        with self.assertRaises(LabError):
            self.lab.encrypt(1)
        self.assertEqual(p.read_bytes(), b"Meow-meow!\n")
        self.assertEqual(collision.read_bytes(), b"existing output")
        collision.unlink()
        with self.assertRaises(LabError):
            self.lab.encrypt(999)
        self.lab.encrypt(1)
        self.lab.restore()

    def test_restore_will_not_overwrite_a_replacement_source(self):
        p = self.write("source.txt")
        self.lab.encrypt(1)
        p.write_text("new unrelated content")
        with self.assertRaises(LabError):
            self.lab.restore()
        self.assertEqual(p.read_text(), "new unrelated content")
        p.unlink()
        self.lab.restore()
        self.assertEqual(p.read_bytes(), b"Meow-meow!\n")

    def test_restore_rejects_symlink_record(self):
        self.write("source.txt")
        self.lab.encrypt(1)
        p = self.directory / "source.txt.meoware"
        backup = self.directory / "backup"
        p.rename(backup)
        p.symlink_to(backup)
        with self.assertRaises(LabError):
            self.lab.restore()
        p.unlink()
        backup.rename(p)
        self.lab.restore()

    def test_root_descriptor_survives_path_replacement(self):
        self.write("fixture.txt")
        moved = self.directory.with_name(self.directory.name + "-moved")
        with tempfile.TemporaryDirectory(prefix="meoware-unrelated-test-") as outside:
            sentinel = Path(outside) / "untouched.txt"
            sentinel.write_text("untouched")
            self.directory.rename(moved)
            self.directory.symlink_to(outside, target_is_directory=True)
            try:
                self.lab.encrypt(1)
                self.lab.restore()
                self.assertEqual((moved / "fixture.txt").read_bytes(), b"Meow-meow!\n")
                self.assertEqual(sentinel.read_text(), "untouched")
                self.assertEqual(len(list(Path(outside).iterdir())), 1)
            finally:
                self.directory.unlink()
                moved.rename(self.directory)

    def test_deadline_only_removes_this_sessions_records(self):
        self.write("fixture.txt")
        self.lab.encrypt(1)
        extra = self.write("not-in-session.txt", b"leave this alone")
        self.lab.expire()
        self.assertEqual(self.lab.state, 3)
        self.assertEqual(extra.read_bytes(), b"leave this alone")
        self.assertFalse(list(self.directory.rglob("*.meoware")))
        with self.assertRaises(LabError):
            self.lab.restore()

    def test_import_refuses_populated_and_active_labs(self):
        self.write("original.txt")
        with self.assertRaises(LabError):
            self.lab.import_corpus(ROOT / "datasets/corpora/smoke-42")
        self.lab.encrypt(1)
        with self.assertRaises(LabError):
            self.lab.import_corpus(ROOT / "datasets/corpora/smoke-42")
        self.lab.restore()


if __name__ == "__main__":
    unittest.main()
