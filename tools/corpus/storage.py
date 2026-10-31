"""Bounded artifact creation and independent integrity verification."""

import hashlib
import json
import math
import os
import shutil
import stat
from collections import Counter
from pathlib import Path

from .formats import CHUNK, Content
from .model import CorpusError, canonical, corpus_id, digest, integer, relative_path, source_plan, unique_fields


class LimitedFile:
    """Seekable output budget, including ZIP/WAV header rewrites."""

    def __init__(self, raw, limit):
        self.raw, self.limit = raw, limit

    def write(self, data):
        if self.raw.tell() + len(data) > self.limit:
            raise CorpusError("payload exceeds --max-bytes; increase the explicit budget or reduce the profile")
        return self.raw.write(data)

    def __getattr__(self, name):
        return getattr(self.raw, name)


def statistics(path):
    counts = Counter()
    hasher = hashlib.sha256()
    prefix = bytearray()
    size = 0
    with path.open("rb") as file:
        while data := file.read(CHUNK):
            hasher.update(data)
            counts.update(data)
            size += len(data)
            prefix.extend(data[:max(0, CHUNK - len(prefix))])
    histogram = [counts[i] for i in range(256)]
    entropy = -sum((count / size) * math.log2(count / size) for count in histogram if count) if size else 0.0
    import zlib
    return {"size_bytes": size, "sha256": hasher.hexdigest(), "byte_histogram": histogram,
            "shannon_entropy_bits_per_byte": entropy,
            "prefix_sample_bytes": len(prefix),
            "prefix_zlib_ratio": len(zlib.compress(prefix, 6)) / len(prefix) if prefix else None}


def generate(destination, planned, registry):
    destination = Path(destination)
    # Refuse reuse even for an empty directory: it may contain an existing experiment.
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    try:
        (destination / ".incomplete").write_text("generation in progress\n", encoding="ascii")
        payload = destination / "payload"
        payload.mkdir()
        used, index_hash = 0, hashlib.sha256()
        with (destination / "files.jsonl").open("xb") as index_file:
            for group, index, source_id, size in source_plan(planned["profile"], planned["seed"]):
                spec = registry[group["format"]]
                source_path = None
                for copy_index in range(group["copies"]):
                    relative = f"{group['directory']}/{group['id']}-{index:06d}-{copy_index:03d}.{spec.extension}"
                    relative_path(relative)
                    path = payload.joinpath(*relative.split("/"))
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("x+b") as raw:
                        output = LimitedFile(raw, planned["limits"]["max_bytes"] - used)
                        if source_path is None:
                            spec.write(output, Content(source_id, group["content"], group["text"]), size)
                        else:
                            with source_path.open("rb") as source:
                                shutil.copyfileobj(source, output, CHUNK)
                        raw.flush()
                    source_path = path if source_path is None else source_path
                    metrics = statistics(path)
                    used += metrics["size_bytes"]
                    record = {"schema_version": 1, "corpus_id": planned["corpus_id"],
                              "file_id": digest([planned["corpus_id"], source_id, copy_index]),
                              "source_group_id": source_id, "dedup_group_id": metrics["sha256"],
                              "relative_path": relative, "group_id": group["id"],
                              "format": spec.name, "format_version": spec.version,
                              "media_type": spec.media_type, "copy_index": copy_index,
                              "content_mode": group["content"], "content_seed": source_id,
                              "requested_content_bytes": size, "role": "unlabeled_synthetic_fixture",
                              **metrics}
                    line = (canonical(record) + "\n").encode("ascii")
                    index_hash.update(line)
                    index_file.write(line)
        manifest = {**planned, "payload_bytes": used, "files_index": "files.jsonl",
                    "files_index_sha256": index_hash.hexdigest(), "payload_directory": "payload"}
        (destination / "manifest.json").write_text(canonical(manifest) + "\n", encoding="ascii")
        (destination / ".incomplete").unlink()
        return {"status": "generated", "corpus_id": planned["corpus_id"],
                "directory": str(destination), "file_count": planned["file_count"], "payload_bytes": used}
    except BaseException:
        # Only remove the newly reserved output, never a pre-existing corpus.
        shutil.rmtree(destination)
        raise


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise CorpusError(f"not a regular file: {path}")


def linklike(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def verify(directory, payload_override=None):
    directory = Path(directory)
    if linklike(directory) or (directory / ".incomplete").exists():
        raise CorpusError("corpus is a symlink or has an incomplete generation marker")
    manifest_path = directory / "manifest.json"
    regular(manifest_path)
    if manifest_path.stat().st_size > 16 * 1024 * 1024:
        raise CorpusError("manifest is too large")
    manifest = json.loads(manifest_path.read_text(encoding="ascii"), object_pairs_hook=unique_fields)
    if (manifest.get("schema_version") != 1 or manifest.get("files_index") != "files.jsonl"
            or manifest.get("payload_directory") != "payload"):
        raise CorpusError("unsupported manifest layout")
    count = integer(manifest["file_count"], "file_count", 1, 100000)
    if corpus_id(manifest["profile"], manifest["seed"], manifest["generator"]) != manifest["corpus_id"]:
        raise CorpusError("manifest corpus_id does not match its recipe")
    payload = Path(payload_override) if payload_override is not None else directory / "payload"
    if linklike(payload) or not payload.is_dir():
        raise CorpusError("payload must be a real directory")
    index_path = directory / "files.jsonl"
    regular(index_path)
    expected_paths, file_ids = set(), set()
    total, index_hash = 0, hashlib.sha256()
    with index_path.open("rb") as index_file:
        for _ in range(count):
            line = index_file.readline(65537)
            if not line or len(line) > 65536 or not line.endswith(b"\n"):
                raise CorpusError("truncated or oversized files.jsonl record")
            index_hash.update(line)
            record = json.loads(line, object_pairs_hook=unique_fields)
            relative = record["relative_path"]
            parts = relative_path(relative).parts
            if (record["schema_version"] != 1 or record["corpus_id"] != manifest["corpus_id"]
                    or relative.casefold() in expected_paths or record["file_id"] in file_ids):
                raise CorpusError("inconsistent or duplicate files.jsonl record")
            expected_paths.add(relative.casefold())
            file_ids.add(record["file_id"])
            path = payload
            for part in parts:
                path = path / part
                if linklike(path):
                    raise CorpusError(f"payload contains a symlink: {relative}")
            regular(path)
            actual = statistics(path)
            if any(actual[key] != record[key] for key in ("size_bytes", "sha256", "byte_histogram")):
                raise CorpusError(f"file differs from manifest: {relative}")
            if record["dedup_group_id"] != actual["sha256"]:
                raise CorpusError(f"invalid dedup group: {relative}")
            total += actual["size_bytes"]
        if index_file.read(1):
            raise CorpusError("files.jsonl has extra records")
    if index_hash.hexdigest() != manifest["files_index_sha256"] or total != manifest["payload_bytes"]:
        raise CorpusError("index digest or payload total differs from manifest")
    found = set()
    def walk_error(error):
        raise error

    for base, directories, files in os.walk(payload, followlinks=False, onerror=walk_error):
        for name in directories:
            if linklike(Path(base) / name):
                raise CorpusError("payload contains a directory symlink")
        for name in files:
            path = Path(base) / name
            regular(path)
            relative = path.relative_to(payload).as_posix().casefold()
            if relative in found:
                raise CorpusError("payload has Windows case-colliding names")
            found.add(relative)
    if found != expected_paths:
        raise CorpusError("payload contains unlisted or missing files")
    return {"status": "verified", "corpus_id": manifest["corpus_id"],
            "file_count": count, "payload_bytes": total}
