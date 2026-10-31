# Reproducible corpus fixtures

This tool generates synthetic files for controlled file-I/O experiments. It is independent of Meoware's C code and encryption algorithms. It runs on Python 3.10+ using only the standard library. It does not execute profile code, download files, encrypt data, or capture telemetry.

## Generate and verify

Run from the repository root:

```bash
python3 -m tools.corpus formats
python3 -m tools.corpus plan --profile tools/corpus/profiles/smoke.json --seed 42
python3 -m tools.corpus generate --profile tools/corpus/profiles/smoke.json --seed 42 --output datasets/corpora/smoke-42
python3 -m tools.corpus verify --corpus datasets/corpora/smoke-42
```

`plan` validates the profile and budgets without writing files. `generate` refuses existing output paths, including empty directories. It writes an `.incomplete` marker until completion and cleans up its newly created output after a handled failure. A hard crash can leave an incomplete directory; `verify` refuses it. No existing experiment is overwritten.

The default limits are 10,000 output files, 256 MiB of actual payload, and 256 MiB of requested content. Content limits are checked before generation; actual output limits are enforced as bytes are written, including format headers and ZIP header rewrites. `--max-bytes` covers payload files, not metadata or temporary filesystem overhead. `--max-content-bytes` limits generation work for highly compressible files even when their output would be small. Set larger limits explicitly when an experiment requires them:

```bash
python3 -m tools.corpus generate --profile tools/corpus/profiles/workstation.json --seed 20261031 --max-bytes 268435456 --max-content-bytes 268435456 --output datasets/corpora/workstation-20261031
```

The workstation profile is a convenience mixture, not an empirically measured office distribution. `bin` files are explicit synthetic controls. PNGs are flat or noisy synthetic images, WAVs contain synthetic PCM, and document text comes from a small synthetic grammar. No photographs, speech, or genuine office usage are implied.

## Artifact layout and transfer

```text
<output>/
  manifest.json       # recipe, corpus ID, toolchain, totals, index digest
  files.jsonl         # one record per payload file
  payload/           # transferable directory tree
```

Copy only the **contents** of `payload/` into Meoware's displayed `CryptPath`. The GUI creates a fresh folder at each launch. Preserve the original corpus separately. Keep manifests and collector logs outside `CryptPath`: the simulator processes all regular files inside it. Restoring requires keeping that Meoware process open. Meoware stages ciphertext alongside originals, so provision additional VM disk space beyond the payload size for ciphertext and logs.

The corpus metadata contains only relative POSIX paths with portable ASCII components. Generated paths reject traversal, Windows device names, trailing dots/spaces, and excessive length. The existing Windows simulator still uses ANSI APIs and `MAX_PATH`; the full VM destination path also has to fit its limit.

To compare restored/copied files against the original manifest:

```bash
python3 -m tools.corpus verify --corpus datasets/corpora/smoke-42 --payload /path/to/copied-or-restored/payload
```

Verification checks file bytes, sizes, histograms, index hash, totals, missing/extra files, and symlinks. It is read-only and requires no cipher knowledge. These checks detect differences relative to a trusted manifest; an attacker who replaces the files and manifest together can replace their hashes too. Archive the original metadata with your experiment records.

## Profile API

[`profiles/profile.schema.json`](profiles/profile.schema.json) describes the JSON shape. Runtime validation additionally checks registered writers, compatible content modes, unique group IDs, Windows-safe paths, range ordering, and budgets. Unknown fields are errors. Profiles contain data only; there are no executable expressions or import hooks.

```json
{
  "schema_version": 1,
  "name": "my-documents-v1",
  "groups": [
    {
      "id": "reports",
      "format": "pdf",
      "directory": "Documents/Reports",
      "count": 6,
      "copies": 2,
      "content_bytes": [1024, 4096, 65537],
      "content": "text",
      "text": "Meow-meow! Project observations. "
    }
  ]
}
```

- `count` is the number of logical sources; `copies` defaults to 1 and produces exact copies of each source. This example creates 12 files and six source groups.
- An explicit `content_bytes` list is cycled by source index, guaranteeing each listed position occurs either floor(count/list-length) or ceil(count/list-length) times. Copies repeat those assignments. With `count` at least the list length, every listed size is covered.
- `content_bytes: {"min": 1024, "max": 65536}` selects an inclusive size deterministically using SHA-256 and rejection sampling. There is no claim that this uniform size policy matches real user data.
- `content_bytes` measures requested source content, **not the final file size**. TXT and BIN preserve the requested size. Documents add structure, DOCX/ZIP/PNG compress, PNG rounds to RGB rows, and WAV rounds to complete 16-bit samples. The actual size is always recorded.
- `text` and `repeat` work in all formats. Binary/media/archive writers also allow `random`, `zeros`, and `mixed`. `random` uses deterministic SHAKE-256 output; `mixed` alternates textual and pseudorandom 64 KiB content blocks. These names describe source construction, not measured entropy classes. Custom `text` is printable ASCII, up to 4,096 characters.
- Seeds are unsigned 64-bit integers. Per-source seed derivation includes the master seed, stable group ID, and logical source index. Adding sources to another group preserves existing source content.

`repeat` is a continuous repetition of the configured ASCII text, including across internal 64 KiB I/O blocks. Version 1.0.1 fixes a phase reset at those boundaries in 1.0.0 when the template length did not divide 65,536. This removes an unintended buffer-aligned discontinuity. Previously generated corpora remain verifiable against their own manifests; regenerating with the new version records a new generator fingerprint and corpus ID.

## Reproduction and extension

The same normalized profile, seed, generator source, Python version, and zlib runtime version produce the same byte artifacts in the tested environment. No wall-clock timestamps, absolute output paths, random UUIDs, or host names enter the artifact metadata. ZIP members use a fixed timestamp. The manifest records the generator version, source fingerprint, Python and zlib versions, normalized profile, and corpus ID. Pin these when reproducing an experiment; different toolchains can produce different compressed bytes. File mtimes and filesystem allocation are not part of byte reproducibility or identical I/O performance.

`formats.py` registers writers with a name, extension, MIME type, compatible modes, and writer version. To add a format, implement a streaming writer with the same `(output, source, requested_content_bytes)` contract and register it. Preserve valid format structure, budget enforcement through the supplied output, deterministic metadata, bounded content reads, and reader-based tests. No profile, telemetry schema, or cipher dispatch modification is needed for a new encryption algorithm.

File content is handled in 64 KiB chunks; PDF rendering buffers one small page at a time and keeps its xref metadata proportional to page count. The generator does not allocate a buffer equal to an entire file. It also streams the JSONL index rather than keeping all file records in RAM. Verification keeps sets of paths/IDs proportional to file count.

## Statistics and future model training

Each `files.jsonl` record contains:

- `file_id`, `corpus_id`, relative path, format and writer version, group, content seed/mode, requested and actual sizes.
- `source_group_id`: stable logical lineage across copies and profile variants sharing the seed/group/index.
- `dedup_group_id`: SHA-256 of the actual file bytes, catching exact duplicates across different sources and corpora, including empty files.
- SHA-256, a 256-element exact byte histogram, empirical Shannon entropy, and compression ratio of at most the first 64 KiB.
- `role: "unlabeled_synthetic_fixture"`. There is no ransomware, benign-process, or algorithm class label.

For n > 0 bytes and counts c_i, the statistic is H = -sum((c_i/n) log2(c_i/n)), omitting zero counts. Therefore sum(c_i) = n and 0 <= H <= 8 bits/byte. Empty files use H = 0 by convention. This is a whole-file empirical marginal byte statistic, not cryptographic entropy, an entropy rate, or a proof of encryption. Prefix compression ratio is compressed prefix length / original prefix length and is null for an empty prefix; it may exceed 1 for short or incompressible inputs.

JSONL gives a stable row interface for later conversion to Arrow/Parquet or numeric tensors. Keep the original manifests: future converters can change without regenerating fixtures. The telemetry collector and time-window feature extraction are separate components; this corpus generator does not provide process-event training examples.

For evaluation:

1. Collect paired benign workloads and bounded simulation runs on the same corpus profiles. Keep encryption and restore intervals distinct. Record corpus ID, executable version, VM configuration, scenario, and telemetry loss in run metadata.
2. Keep all windows from a run together. Group related corpora and repeated runs conservatively; account for both shared source lineage and exact byte duplicates across corpora. Use connected groups when either relation links samples. Different seeds alone do not establish statistical independence, and common templates can cause near-duplicate leakage.
3. Exclude IDs, paths, hashes, seeds, profile/writer identifiers and scenario labels from default prediction features. Metadata and post-run outcome measurements are not automatically available at prediction time.
4. Compare against a simple baseline and evaluate on held-out workloads, days, machines, and independently sourced/lawfully obtained data. Report false alarms per benign machine-hour, detection delay, affected files/bytes, collector overhead, and uncertainty. A synthetic-only benchmark cannot establish effectiveness on in-the-wild ransomware.

What is established here is deterministic generation, explicit coverage policy, integrity, and defined byte statistics. Usefulness for an unspecified future model or real-world distribution cannot be mathematically guaranteed by this generator. Entropy alone is insufficient to establish encryption: see [Davies et al., Comparison of Entropy Calculation Methods for Ransomware Encrypted File Identification](https://arxiv.org/abs/2210.13376). See also [scikit-learn's guidance on data leakage](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).

## Checks

```bash
python3 -m unittest discover -s tests/corpus -v
```

The standard-library tests cover determinism, seed variation, duplicates, malformed profiles, path traversal, quotas, corruption, independent ZIP/XML/WAV/PNG reading, statistical invariants, and bounded streaming memory. If `pypdf` is installed, an additional independent PDF parser check runs. The existing C/Windows tests and application build are independent of these tests.
