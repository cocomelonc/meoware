"""Streaming, standard-library format writers; add formats via register()."""

import csv
import hashlib
import io
import json
import struct
import wave
import zipfile
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Callable
from xml.sax.saxutils import escape

CHUNK = 65536
TEXT_MODES = ("text", "repeat")
ALL_MODES = TEXT_MODES + ("random", "zeros", "mixed")
REGISTRY = {}


@dataclass(frozen=True)
class Format:
    name: str
    extension: str
    media_type: str
    modes: tuple
    write: Callable[[BinaryIO, "Content", int], None]
    version: int = 1


def register(name, extension, media_type, modes=ALL_MODES):
    def decorate(writer):
        if name in REGISTRY:
            raise ValueError(f"duplicate format: {name}")
        REGISTRY[name] = Format(name, extension, media_type, modes, writer)
        return writer
    return decorate


class Content:
    """Bounded deterministic source. SHAKE output is synthetic, not user data."""

    def __init__(self, seed, mode, text):
        self.seed = bytes.fromhex(seed)
        self.mode, self.text, self.counter, self.buffer = mode, text.encode("ascii"), 0, b""

    def block(self):
        counter = self.counter
        self.counter += 1
        mode = self.mode
        if mode == "mixed":
            mode = "text" if counter % 2 == 0 else "random"
        if mode == "zeros":
            return bytes(CHUNK)
        if mode == "repeat":
            # Preserve the pattern's phase across internal I/O block boundaries.
            phase = (counter * CHUNK) % len(self.text)
            pattern = self.text[phase:] + self.text[:phase]
            return (pattern * (CHUNK // len(pattern) + 1))[:CHUNK]
        noise = hashlib.shake_256(self.seed + counter.to_bytes(8, "little")).digest(CHUNK)
        if mode == "random":
            return noise
        nouns = ("report", "project", "meeting", "budget", "invoice", "archive", "research", "schedule")
        verbs = ("reviewed", "updated", "approved", "recorded", "checked", "scheduled", "discussed", "prepared")
        lines, length = [], 0
        for i in range(0, 8192, 4):
            line = (f"{self.text} The {nouns[noise[i] % 8]} was {verbs[noise[i+1] % 8]} "
                    f"for item {int.from_bytes(noise[i+2:i+4], 'little'):05d}.\n")
            lines.append(line)
            length += len(line)
            if length >= CHUNK:
                break
        return "".join(lines).encode("ascii")[:CHUNK]

    def read(self, count):
        if not 0 <= count <= CHUNK:
            raise ValueError("content reads must be bounded by CHUNK")
        result = bytearray()
        while len(result) < count:
            if not self.buffer:
                self.buffer = self.block()
            take = min(count - len(result), len(self.buffer))
            result.extend(self.buffer[:take])
            self.buffer = self.buffer[take:]
        return bytes(result)


def chunks(source, size, chunk_size=CHUNK):
    while size:
        take = min(size, chunk_size)
        yield source.read(take)
        size -= take


@register("bin", "bin", "application/octet-stream")
def binary(out, source, size):
    for data in chunks(source, size):
        out.write(data)


@register("txt", "txt", "text/plain", TEXT_MODES)
def text(out, source, size):
    binary(out, source, size)


@register("csv", "csv", "text/csv", TEXT_MODES)
def csv_file(out, source, size):
    out.write(b"record_id,text\r\n")
    for index, data in enumerate(chunks(source, size, 256)):
        line = io.StringIO(newline="")
        csv.writer(line).writerow([index, data.decode("ascii")])
        out.write(line.getvalue().encode("ascii"))


@register("json", "json", "application/json", TEXT_MODES)
def json_file(out, source, size):
    out.write(b'{"records":[')
    for index, data in enumerate(chunks(source, size, 256)):
        if index:
            out.write(b",")
        out.write(json.dumps({"record_id": index, "text": data.decode("ascii")},
                             separators=(",", ":")).encode("ascii"))
    out.write(b"]}\n")


@register("pdf", "pdf", "application/pdf", TEXT_MODES)
def pdf(out, source, size):
    pages = max(1, (size + 2999) // 3000)
    offsets = [0]
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    def obj(number, data):
        offsets.append(out.tell())
        out.write(f"{number} 0 obj\n".encode("ascii") + data + b"\nendobj\n")

    obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{4 + i * 2} 0 R" for i in range(pages))
    obj(2, f"<< /Type /Pages /Kids [{kids}] /Count {pages} >>".encode("ascii"))
    obj(3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    remaining = size
    for page in range(pages):
        number = 4 + page * 2
        obj(number, (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                     f"/Resources << /Font << /F1 3 0 R >> >> /Contents {number+1} 0 R >>").encode("ascii"))
        count = min(3000, remaining)
        data = source.read(count).replace(b"\n", b" ")
        remaining -= count
        stream = bytearray(b"BT\n/F1 10 Tf\n13 TL\n50 790 Td\n")
        for start in range(0, len(data), 80):
            line = data[start:start+80].replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
            stream.extend(b"(" + line + b") Tj\nT*\n")
        stream.extend(b"ET\n")
        obj(number + 1, f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"endstream")
    xref = out.tell()
    out.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        if offset >= 10**10:
            raise ValueError("PDF exceeds classic xref offset range")
        out.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))


def zip_info(name):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 0
    info.external_attr = 0x20
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


@register("docx", "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", TEXT_MODES)
def docx(out, source, size):
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr(zip_info("[Content_Types].xml"),
                         '<?xml version="1.0" encoding="UTF-8"?>'
                         '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                         '<Default Extension="xml" ContentType="application/xml"/>'
                         '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                         '</Types>')
        archive.writestr(zip_info("_rels/.rels"),
                         '<?xml version="1.0" encoding="UTF-8"?>'
                         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                         '</Relationships>')
        with archive.open(zip_info("word/document.xml"), "w", force_zip64=size > zipfile.ZIP64_LIMIT // 8) as document:
            document.write(b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>')
            for data in chunks(source, size, 1000):
                document.write(b'<w:p><w:r><w:t xml:space="preserve">' + escape(data.decode("ascii")).encode("ascii") + b'</w:t></w:r></w:p>')
            document.write(b'<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr></w:body></w:document>')


@register("zip", "zip", "application/zip")
def zip_file(out, source, size):
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        with archive.open(zip_info("payload.dat"), "w", force_zip64=size > zipfile.ZIP64_LIMIT // 2) as member:
            binary(member, source, size)


@register("png", "png", "image/png")
def png(out, source, size):
    width = max(1, min(256, (size + 2) // 3))
    row_size = width * 3
    height = max(1, (size + row_size - 1) // row_size)
    if height > 2**31 - 1:
        raise ValueError("PNG dimensions exceed specification limits")
    out.write(b"\x89PNG\r\n\x1a\n")

    def block(kind, data):
        out.write(struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data)))

    block(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    compressor = zlib.compressobj(6)
    remaining = size
    for _ in range(height):
        count = min(remaining, row_size)
        row = b"\0" + source.read(count) + bytes(row_size - count)
        remaining -= count
        compressed = compressor.compress(row)
        if compressed:
            block(b"IDAT", compressed)
    block(b"IDAT", compressor.flush())
    block(b"IEND", b"")


@register("wav", "wav", "audio/wav")
def wav(out, source, size):
    if size > 2**32 - 46:
        raise ValueError("WAV exceeds RIFF size limit")
    with wave.open(out, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.setnframes((size + 1) // 2)
        for data in chunks(source, size):
            if len(data) % 2:
                data += b"\0"
            audio.writeframesraw(data)
