"""Strict declarative profiles and deterministic generation plans."""

import hashlib
import json
import platform
import re
import zlib
from pathlib import Path, PurePosixPath

from . import VERSION


class CorpusError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorpusError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def integer(value, name, minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise CorpusError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def keys(value, allowed, required, name):
    if not isinstance(value, dict):
        raise CorpusError(f"{name} must be an object")
    if set(value) - allowed or required - set(value):
        raise CorpusError(f"{name}: unexpected or missing fields")


def relative_path(value):
    if not isinstance(value, str) or not value or len(value) > 120:
        raise CorpusError("relative paths must contain 1..120 ASCII characters")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or "\\" in value:
        raise CorpusError("paths must be normalized relative POSIX paths")
    for part in path.parts:
        base = part.split(".")[0].rstrip(" ").upper()
        if (part in (".", "..") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]*", part)
                or part.endswith((".", " ")) or len(part) > 64
                or base in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9]", base)):
            raise CorpusError(f"nonportable or unsafe path component: {part!r}")
    return path


def load_profile(path, registry):
    try:
        if Path(path).stat().st_size > 16 * 1024 * 1024:
            raise CorpusError("profile is too large")
        profile = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_fields)
    except (OSError, ValueError) as exc:
        raise CorpusError(f"cannot read profile: {exc}") from exc
    keys(profile, {"schema_version", "name", "groups"}, {"schema_version", "name", "groups"}, "profile")
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise CorpusError("unsupported profile schema_version")
    if not isinstance(profile["name"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", profile["name"]):
        raise CorpusError("profile name must be a lowercase slug")
    if not isinstance(profile["groups"], list) or not 1 <= len(profile["groups"]) <= 1000:
        raise CorpusError("profile needs 1..1000 groups")
    groups, seen = [], set()
    for raw in profile["groups"]:
        keys(raw, {"id", "format", "directory", "count", "copies", "content_bytes", "content", "text"},
             {"id", "format", "directory", "count", "content_bytes", "content"}, "group")
        group = dict(raw)
        ident = group["id"]
        if not isinstance(ident, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", ident) or ident in seen:
            raise CorpusError("group ids must be unique lowercase slugs")
        seen.add(ident)
        if not isinstance(group["format"], str) or group["format"] not in registry:
            raise CorpusError(f"unknown format in group {ident}")
        spec = registry[group["format"]]
        if not isinstance(group["content"], str) or group["content"] not in spec.modes:
            raise CorpusError(f"unsupported content mode for {spec.name}: {group['content']!r}")
        relative_path(group["directory"])
        integer(group["count"], "count", 1, 100000)
        group["copies"] = integer(group.get("copies", 1), "copies", 1, 1000)
        group["text"] = group.get("text", "Meow-meow! Synthetic laboratory document. ")
        if (not isinstance(group["text"], str) or not 1 <= len(group["text"]) <= 4096
                or any(ord(c) < 32 or ord(c) > 126 for c in group["text"])):
            raise CorpusError("text must contain 1..4096 printable ASCII characters")
        sizes = group["content_bytes"]
        if isinstance(sizes, list):
            if not 1 <= len(sizes) <= 10000:
                raise CorpusError("content_bytes list needs 1..10000 entries")
            for size in sizes:
                integer(size, "content_bytes")
        else:
            keys(sizes, {"min", "max"}, {"min", "max"}, "content_bytes")
            integer(sizes["min"], "content_bytes.min")
            integer(sizes["max"], "content_bytes.max", sizes["min"])
        relative_path(f"{group['directory']}/{ident}-000000-000.{spec.extension}")
        groups.append(group)
    return {"schema_version": 1, "name": profile["name"], "groups": groups}


def implementation():
    hasher = hashlib.sha256()
    for path in sorted(Path(__file__).parent.glob("*.py")):
        hasher.update(path.name.encode("ascii") + b"\0" + path.read_bytes() + b"\0")
    return {"name": "meoware-corpus", "version": VERSION, "source_sha256": hasher.hexdigest(),
            "python": platform.python_version(), "zlib": zlib.ZLIB_RUNTIME_VERSION}


def corpus_id(profile, seed, generator):
    return digest({"profile": profile, "seed": seed, "generator": generator})


def source_plan(profile, seed):
    """An explicit size list is cycled; ranges use deterministic uniform sampling."""
    for group in profile["groups"]:
        for index in range(group["count"]):
            source_id = digest(["meoware-source-v1", seed, group["id"], index])
            sizes = group["content_bytes"]
            if isinstance(sizes, list):
                size = sizes[index % len(sizes)]
            else:
                span = sizes["max"] - sizes["min"] + 1
                # Rejection sampling avoids modulo bias, unlike hash % span.
                cutoff = 2**256 - (2**256 % span)
                attempt = 0
                while True:
                    value = int(digest([source_id, "size", attempt]), 16)
                    if value < cutoff:
                        size = sizes["min"] + value % span
                        break
                    attempt += 1
            yield group, index, source_id, size


def plan(profile, seed, registry, max_files, max_bytes, max_content_bytes):
    integer(seed, "seed", 0, 2**64 - 1)
    integer(max_files, "max_files", 1, 100000)
    integer(max_bytes, "max_bytes", 1)
    integer(max_content_bytes, "max_content_bytes", 1)
    file_count = sum(g["count"] * g["copies"] for g in profile["groups"])
    if file_count > max_files:
        raise CorpusError(f"planned {file_count} files exceed --max-files={max_files}")
    content_total = sum(size * g["copies"] for g, _, _, size in source_plan(profile, seed))
    if content_total > max_content_bytes:
        raise CorpusError(f"planned content bytes {content_total} exceed --max-content-bytes={max_content_bytes}")
    generator = implementation()
    return {"schema_version": 1, "corpus_id": corpus_id(profile, seed, generator), "seed": seed,
            "generator": generator, "profile": profile, "file_count": file_count,
            "requested_content_bytes": content_total,
            "limits": {"max_files": max_files, "max_bytes": max_bytes,
                       "max_content_bytes": max_content_bytes},
            "coverage": [{"group_id": g["id"], "format": g["format"], "content": g["content"],
                          "sources": g["count"], "files": g["count"] * g["copies"],
                          "size_values_covered": len(set(g["content_bytes"][:g["count"]]))
                          if isinstance(g["content_bytes"], list) else None}
                         for g in profile["groups"]]}
