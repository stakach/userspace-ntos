"""Check the exact native executor milestones requested for one stopped KVM boot."""

import argparse
from pathlib import Path
import sys


PROBES = (
    ("passive worker", b"[executor-passive-worker-probe]"),
    ("fault supervisor", b"[executor-fault-supervisor-probe]"),
    ("production worker", b"[executor-production-worker]"),
)


def verify_probe_markers(log: bytes, *, require_passive=False, require_supervisor=False):
    """Return failures; a later PASS cannot erase a prior refusal in this boot."""
    required = PROBES if require_supervisor else PROBES[:1] if require_passive else ()
    if not required:
        return []
    lines = [line.strip() for line in log.splitlines()]
    errors = []
    pass_positions = []
    for name, marker in required:
        if any(line.startswith(marker + b" FAIL") for line in lines):
            errors.append(f"{name} reported a native refusal")
        passes = [index for index, line in enumerate(lines) if line == marker + b" PASS"]
        if not passes:
            errors.append(f"{name} did not pass its native proof")
        else:
            pass_positions.append(passes[0])
    if len(pass_positions) == len(required) and pass_positions != sorted(set(pass_positions)):
        errors.append("native executor proofs appeared out of order")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--require-passive", action="store_true")
    parser.add_argument("--require-supervisor", action="store_true")
    args = parser.parse_args(argv)
    try:
        log = args.log.read_bytes()
    except OSError as error:
        parser.error(str(error))
    errors = verify_probe_markers(
        log,
        require_passive=args.require_passive,
        require_supervisor=args.require_supervisor,
    )
    for error in errors:
        print(f"native executor proof: {error}", file=sys.stderr)
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
