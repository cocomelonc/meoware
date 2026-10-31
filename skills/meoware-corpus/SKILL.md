---
name: meoware-corpus
description: Generate and verify reproducible synthetic file corpora for Meoware lab experiments using JSON profiles. Use for corpus design, generation, transfer instructions, and integrity checks; telemetry capture and encryption are separate workflows.
---

Use the repository containing this skill. Commands below run from that repository's root. Read `tools/corpus/README.md` for schema semantics, extension points, and research limitations. The skill is plain Markdown and the CLI uses JSON; another agent runner may load it by its own skill installation mechanism.

1. Inspect `python3 -m tools.corpus formats` and an existing profile. Create a declarative JSON profile when the requested corpus differs. The generator accepts no shell commands, Python expressions, remote URLs, or executable hooks in profiles.
2. Choose an explicit seed and a new output directory under `datasets/corpora/`. Run `plan` with explicit file and byte budgets before `generate`. If the request omits scale, use the smoke profile and default 256 MiB limits. Increase limits only to match a requested experiment; a budget failure is a reason to inspect the plan.
3. Run `generate`, then `verify`. Report the corpus ID, file count, actual bytes, seed, and profile. Existing outputs are refused; choose another directory rather than deleting an experiment to retry.
4. For the Windows lab, copy only the contents of `payload/` into the folder shown by **Open lab folder**. Keep `manifest.json` and `files.jsonl` outside that folder. After restoration, `verify --payload <restored-folder>` compares against the original corpus metadata.

Example:

```bash
python3 -m tools.corpus plan --profile tools/corpus/profiles/smoke.json --seed 42
python3 -m tools.corpus generate --profile tools/corpus/profiles/smoke.json --seed 42 --output datasets/corpora/smoke-42
python3 -m tools.corpus verify --corpus datasets/corpora/smoke-42
```

Keep corpus generation independent of cipher selection: use the same corpus in comparable runs of different algorithms, and store algorithm/scenario labels in run metadata. Do not treat generated files as ransomware samples or claim that these fixtures constitute a labeled telemetry dataset. They have no attack labels.

For future ML splits, keep all observations of a corpus/run together and account for both `source_group_id` and `dedup_group_id` across corpora. Different seeds do not prove independence or realism. Corpus IDs, paths, hashes, seeds, format-writer versions, and scenario labels are provenance, not default model inputs. Changes to format writers require their version and the generator version to be reviewed, followed by determinism and format-validation tests.
