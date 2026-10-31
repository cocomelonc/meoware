"""Machine-readable CLI. Run from the repository root: python3 -m tools.corpus."""

import argparse
import json
import sys

from .formats import REGISTRY
from .model import CorpusError, canonical, load_profile, plan
from .storage import generate, verify


class Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({"status": "error", "error": message}), file=sys.stderr)
        self.exit(2)


def main(argv=None):
    parser = Parser(description="Generate reproducible synthetic corpus fixtures; no encryption or telemetry collection.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("formats", help="list built-in format writers and supported content modes")
    for name in ("plan", "generate"):
        sub = commands.add_parser(name)
        sub.add_argument("--profile", required=True)
        sub.add_argument("--seed", type=int, required=True)
        sub.add_argument("--max-files", type=int, default=10000)
        sub.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024, help="actual payload byte budget")
        sub.add_argument("--max-content-bytes", type=int, help="logical content budget; defaults to --max-bytes")
        if name == "generate":
            sub.add_argument("--output", required=True, help="new corpus directory; existing paths are refused")
    sub = commands.add_parser("verify")
    sub.add_argument("--corpus", required=True)
    sub.add_argument("--payload", help="verify an alternate/restored payload tree against the original manifest")
    args = parser.parse_args(argv)
    try:
        if args.command == "formats":
            result = {"formats": [{"name": s.name, "extension": s.extension, "media_type": s.media_type,
                                    "version": s.version, "content_modes": s.modes} for s in REGISTRY.values()]}
        elif args.command == "verify":
            result = verify(args.corpus, args.payload)
        else:
            profile = load_profile(args.profile, REGISTRY)
            planned = plan(profile, args.seed, REGISTRY, args.max_files, args.max_bytes,
                           args.max_content_bytes if args.max_content_bytes is not None else args.max_bytes)
            result = planned if args.command == "plan" else generate(args.output, planned, REGISTRY)
        print(canonical(result))
        return 0
    except (CorpusError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('{"status":"error","error":"interrupted"}', file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
