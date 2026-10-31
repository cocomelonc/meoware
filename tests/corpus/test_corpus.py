"""Behavioral invariants for the standalone corpus generator."""

import copy
import csv
import hashlib
import importlib.util
import io
import json
import struct
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
import wave
import zipfile
import zlib
from pathlib import Path
from xml.etree import ElementTree

from tools.corpus.formats import CHUNK, REGISTRY, Content
from tools.corpus.model import CorpusError, load_profile, plan, relative_path
from tools.corpus.storage import LimitedFile, generate, statistics, verify


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.profile = {"schema_version": 1, "name": "test-v1", "groups": []}
        for name, spec in REGISTRY.items():
            self.profile["groups"].append({"id": name, "format": name, "directory": "Nested/Fixtures",
                                           "count": 3, "content_bytes": [0, 1, 65537],
                                           "content": "text" if name in ("txt", "csv", "json", "pdf", "docx") else "random"})

    def tearDown(self):
        self.temp.cleanup()

    def planned(self, profile=None, seed=42, max_bytes=16 * 1024 * 1024):
        path = self.root / "profile.json"
        path.write_text(json.dumps(profile or self.profile), encoding="utf-8")
        parsed = load_profile(path, REGISTRY)
        return plan(parsed, seed, REGISTRY, 1000, max_bytes, 16 * 1024 * 1024)

    def create(self, name="corpus", profile=None, seed=42):
        path = self.root / name
        generate(path, self.planned(profile, seed), REGISTRY)
        return path

    def test_deterministic_artifacts_and_seed_variation(self):
        first, second = self.create("first"), self.create("second")
        files = sorted(p.relative_to(first) for p in first.rglob("*") if p.is_file())
        for relative in files:
            self.assertEqual((first / relative).read_bytes(), (second / relative).read_bytes(), str(relative))
        self.assertEqual(verify(first)["file_count"], 27)
        other = self.create("other", seed=43)
        self.assertNotEqual((first / "manifest.json").read_bytes(), (other / "manifest.json").read_bytes())
        a = first / "payload/Nested/Fixtures/bin-000002-000.bin"
        b = other / "payload/Nested/Fixtures/bin-000002-000.bin"
        self.assertNotEqual(a.read_bytes(), b.read_bytes())

    def test_formats_with_independent_readers(self):
        root = self.create() / "payload/Nested/Fixtures"
        for index, size in enumerate((0, 1, 65537)):
            suffix = f"-{index:06d}-000"
            self.assertEqual((root / f"bin{suffix}.bin").stat().st_size, size)
            self.assertEqual((root / f"txt{suffix}.txt").stat().st_size, size)
            parsed = json.loads((root / f"json{suffix}.json").read_text())
            self.assertEqual(sum(len(r["text"]) for r in parsed["records"]), size)
            with (root / f"csv{suffix}.csv").open(newline="") as file:
                self.assertEqual(sum(len(r["text"]) for r in csv.DictReader(file)), size)
            with zipfile.ZipFile(root / f"docx{suffix}.docx") as archive:
                self.assertIsNone(archive.testzip())
                for member in archive.namelist():
                    ElementTree.fromstring(archive.read(member))
                xml = ElementTree.fromstring(archive.read("word/document.xml"))
                texts = xml.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
                self.assertEqual(sum(len(node.text or "") for node in texts), size)
                self.assertTrue(all(m.date_time == (1980, 1, 1, 0, 0, 0) for m in archive.infolist()))
            with zipfile.ZipFile(root / f"zip{suffix}.zip") as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(len(archive.read("payload.dat")), size)
            with wave.open(str(root / f"wav{suffix}.wav"), "rb") as audio:
                self.assertEqual(audio.getparams()[:3], (1, 2, 16000))
                self.assertEqual(audio.getnframes(), (size + 1) // 2)
                self.assertEqual(len(audio.readframes(audio.getnframes())), (size + 1) // 2 * 2)
            png = (root / f"png{suffix}.png").read_bytes()
            self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
            position, compressed = 8, bytearray()
            while position < len(png):
                length = struct.unpack_from(">I", png, position)[0]
                kind = png[position+4:position+8]
                data = png[position+8:position+8+length]
                crc = struct.unpack_from(">I", png, position+8+length)[0]
                self.assertEqual(crc, zlib.crc32(kind + data))
                if kind == b"IHDR":
                    width, height = struct.unpack_from(">II", data)
                elif kind == b"IDAT":
                    compressed.extend(data)
                position += 12 + length
            decoded = zlib.decompress(compressed)
            self.assertEqual(len(decoded), height * (1 + width * 3))

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "optional independent PDF parser is not installed")
    def test_pdf_pages_and_escaping(self):
        from pypdf import PdfReader
        profile = copy.deepcopy(self.profile)
        profile["groups"] = [{"id": "pdf", "format": "pdf", "directory": "Docs", "count": 1,
                               "content_bytes": [9001], "content": "repeat", "text": "Meow (test) \\ & <>! "}]
        root = self.create(profile=profile)
        reader = PdfReader(root / "payload/Docs/pdf-000000-000.pdf", strict=True)
        self.assertEqual(len(reader.pages), 4)
        self.assertIn("Meow (test) \\ & <>!", reader.pages[0].extract_text())

    def test_duplicate_lineage_and_integrity_failures(self):
        profile = {"schema_version": 1, "name": "dups", "groups": [
            {"id": "notes", "format": "txt", "directory": "Docs", "count": 1,
             "copies": 3, "content_bytes": [100], "content": "text"}]}
        root = self.create(profile=profile)
        rows = [json.loads(line) for line in (root / "files.jsonl").read_text().splitlines()]
        self.assertEqual(len({r["source_group_id"] for r in rows}), 1)
        self.assertEqual(len({r["dedup_group_id"] for r in rows}), 1)
        self.assertEqual(len({r["file_id"] for r in rows}), 3)
        original = root / "payload" / rows[0]["relative_path"]
        data = original.read_bytes()
        original.write_bytes(b"!" + data[1:])
        with self.assertRaisesRegex(CorpusError, "differs"):
            verify(root)
        original.write_bytes(data)
        extra = root / "payload/extra.txt"
        extra.write_text("unlisted")
        with self.assertRaisesRegex(CorpusError, "unlisted"):
            verify(root)
        extra.unlink()
        self.assertEqual(verify(root, root / "payload")["file_count"], 3)
        index = root / "files.jsonl"
        index.write_bytes(index.read_bytes()[:-1])
        with self.assertRaisesRegex(CorpusError, "truncated"):
            verify(root)

    def test_refuses_existing_paths_and_cleans_budget_failure(self):
        destination = self.root / "existing"
        destination.mkdir()
        sentinel = destination / "keep.txt"
        sentinel.write_text("keep")
        with self.assertRaises(FileExistsError):
            generate(destination, self.planned(), REGISTRY)
        self.assertEqual(sentinel.read_text(), "keep")
        profile = {"schema_version": 1, "name": "limit", "groups": [
            {"id": "doc", "format": "docx", "directory": "Docs", "count": 1,
             "content_bytes": [0], "content": "text"}]}
        with self.assertRaises(CorpusError):
            generate(self.root / "failed", self.planned(profile, max_bytes=10), REGISTRY)
        self.assertFalse((self.root / "failed").exists())
        output = io.BytesIO()
        limited = LimitedFile(output, 4)
        limited.write(b"abcd")
        limited.seek(0)
        limited.write(b"zz")
        with self.assertRaises(CorpusError):
            limited.write(b"123")

    def test_rejects_unsafe_profiles_and_quota_before_generation(self):
        for value in ("../escape", "/absolute", "C:/Windows", "A\\B", "NUL", "foo/CON.txt", "CON .txt", "foo/..", "foo."):
            with self.subTest(value=value), self.assertRaises(CorpusError):
                relative_path(value)
        for change in ({"count": True}, {"content": "random"}, {"format": "exe"},
                       {"exec": "ignored?"}, {"content_bytes": {"min": 2, "max": 1}}):
            profile = copy.deepcopy(self.profile)
            profile["groups"] = [profile["groups"][1]]  # txt accepts only textual modes
            profile["groups"][0].update(change)
            with self.subTest(change=change), self.assertRaises(CorpusError):
                self.planned(profile)
        with self.assertRaises(CorpusError):
            parsed = self.planned()["profile"]
            plan(parsed, 42, REGISTRY, 1, 1000000, 1000000)
        path = self.root / "duplicate-fields.json"
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(CorpusError, "duplicate JSON"):
            load_profile(path, REGISTRY)

    def test_statistics_have_mathematical_invariants(self):
        path = self.root / "bytes.bin"
        for data, entropy in ((b"", 0.0), (bytes(1000), 0.0), (bytes(range(256)) * 16, 8.0)):
            path.write_bytes(data)
            result = statistics(path)
            self.assertEqual(sum(result["byte_histogram"]), len(data))
            self.assertAlmostEqual(result["shannon_entropy_bits_per_byte"], entropy)
            self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())

    def test_repeat_pattern_continues_across_io_blocks(self):
        for pattern in ("abc", "Meow-meow!", "x" * 4094 + "y"):
            with self.subTest(pattern_length=len(pattern)):
                source = Content("a" * 64, "repeat", pattern)
                size = CHUNK * 2 + 17
                actual = source.read(CHUNK) + source.read(CHUNK) + source.read(17)
                expected = (pattern.encode("ascii") * (size // len(pattern) + 1))[:size]
                self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(expected).digest())

    def test_streaming_memory_and_read_boundary_independence(self):
        a = Content("a" * 64, "mixed", "Meow!")
        b = Content("a" * 64, "mixed", "Meow!")
        whole = a.read(CHUNK) + a.read(CHUNK)
        parts = b"".join(b.read(1024) for _ in range(128))
        self.assertEqual(whole, parts)
        path = self.root / "large.bin"
        source = Content("b" * 64, "random", "Meow!")
        tracemalloc.start()
        try:
            with path.open("wb") as out:
                REGISTRY["bin"].write(out, source, 8 * 1024 * 1024)
            statistics(path)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_symlink_refusal_and_cli_errors(self):
        root = self.create()
        if hasattr(Path, "symlink_to"):
            link = root / "payload/link"
            link.symlink_to(self.root, target_is_directory=True)
            with self.assertRaisesRegex(CorpusError, "symlink"):
                verify(root)
            link.unlink()
        command = [sys.executable, "-m", "tools.corpus", "generate", "--profile",
                   "tools/corpus/profiles/smoke.json", "--seed", "42", "--output", str(root)]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["status"], "error")


if __name__ == "__main__":
    unittest.main()
