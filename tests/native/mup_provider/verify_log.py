#!/usr/bin/env python3
"""Verify delivered pending failure and File reference semantics, not native allocation retirement."""

import argparse
import re
from pathlib import Path


PROVIDER = "mup-terminal-failure-"
SOURCE = "terminal-failure-"
SPECS = {
    PROVIDER + "identity": ("provider", {"status": 0, "info": 8}),
    SOURCE + "identity": ("source", {"call": 0, "wait": 0, "iosb": 0, "info": 8}),
    PROVIDER + "pending": ("provider", {"operation": None, "status": 0x103}),
    SOURCE + "retained": ("source", {"operation": None, "event": 0x102, "iosb-and-output-unchanged": 1}),
    PROVIDER + "release": ("provider", {"operation": None}),
    PROVIDER + "terminal-intent": ("provider", {"operation": None, "status": 0xC0000185, "info": 0, "ownership-unchanged": 1}),
    SOURCE + "result": ("source", {"operation": None, "call": 0x103, "release": 0, "wait": 0, "iosb": 0xC0000185, "info": 0, "output-unchanged": 1}),
    SOURCE + "verified": ("source", {"operation": None}),
    SOURCE + "handle-close-begin": ("source", {}),
    SOURCE + "handle-close-return": ("source", {"status": 0}),
    SOURCE + "pointer-release-begin": ("source", {}),
    SOURCE + "pointer-release-return": ("source", {}),
    PROVIDER + "cleanup": ("provider", {"count": 1}),
    PROVIDER + "close": ("provider", {"count": 1}),
}
STATUS_FIELDS = {"status", "call", "release", "wait", "iosb", "event"}


def verify(text):
    records = {}
    for position, line in enumerate(text.splitlines()):
        if "[read-forward-fail]" in line or "[provider-bugcheck] terminal" in line:
            raise ValueError("native fixture or provider failed")
        if "[mup-terminal-failure-" not in line and "[terminal-failure-" not in line:
            continue
        match = re.fullmatch(r"\[([a-z-]+)\] (.+)", line)
        if match is None or match[1] not in SPECS:
            raise ValueError(f"malformed failure receipt: {line}")
        tag = match[1]
        role, expected = SPECS[tag]
        fields = {}
        for item in match[2].split(" "):
            pair = item.split("=")
            if len(pair) != 2 or pair[0] in fields:
                raise ValueError("malformed or duplicate receipt field")
            field, value = pair
            pattern = (r"0x[0-9a-f]{16}" if field in {"file", "generation"}
                       else r"0x[0-9a-f]{8}" if field in STATUS_FIELDS else r"0|[1-9][0-9]*")
            if re.fullmatch(pattern, value) is None:
                raise ValueError(f"malformed scalar {field}")
            fields[field] = int(value, 16 if value.startswith("0x") else 10)
        if set(fields) != {"file", "generation"} | set(expected):
            raise ValueError(f"wrong receipt fields: {tag}")
        if fields["file"] == 0 or fields["generation"] == 0:
            raise ValueError("missing File identity")
        for field, value in expected.items():
            if value is not None and fields[field] != value:
                raise ValueError(f"incorrect native result: {tag}/{field}")
        operation = fields.get("operation")
        if operation is not None and operation not in range(3):
            raise ValueError("unknown operation")
        key = (tag, operation)
        if key in records:
            raise ValueError(f"duplicate receipt: {key}")
        records[key] = (position, role, fields)

    def receipt(tag, operation=None):
        try:
            return records[(tag, operation)]
        except KeyError as error:
            raise ValueError(f"missing receipt: {tag}/{operation}") from error

    source = receipt(SOURCE + "identity")[2]
    provider = receipt(PROVIDER + "identity")[2]
    if source["generation"] != provider["generation"]:
        raise ValueError("FileInternalInformation generation mismatch")
    for _, role, fields in records.values():
        identity = source if role == "source" else provider
        if (fields["file"], fields["generation"]) != (identity["file"], identity["generation"]):
            raise ValueError("stale or foreign File receipt")

    def ordered(*positions):
        if any(left >= right for left, right in zip(positions, positions[1:])):
            raise ValueError("receipt causal order violated")

    prior = receipt(SOURCE + "identity")[0]
    ordered(receipt(PROVIDER + "identity")[0], prior)
    for operation in range(3):
        stages = [receipt(tag, operation)[0] for tag in (
            PROVIDER + "pending", SOURCE + "retained", PROVIDER + "release",
            PROVIDER + "terminal-intent", SOURCE + "result", SOURCE + "verified")]
        ordered(prior, *stages)
        prior = stages[-1]
    close_begin = receipt(SOURCE + "handle-close-begin")[0]
    close_return = receipt(SOURCE + "handle-close-return")[0]
    release_begin = receipt(SOURCE + "pointer-release-begin")[0]
    release_return = receipt(SOURCE + "pointer-release-return")[0]
    cleanup = receipt(PROVIDER + "cleanup")[0]
    close = receipt(PROVIDER + "close")[0]
    ordered(prior, close_begin, close_return, release_begin, release_return)
    # CLEANUP/CLOSE may be deferred beyond the initiating call's return. Intent bounds remain
    # exact: no cleanup before handle close, no final close while the source pointer is retained.
    ordered(close_begin, cleanup, close)
    ordered(release_begin, close)
    return source["file"], provider["file"], source["generation"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-log", required=True, type=Path)
    args = parser.parse_args()
    try:
        source, provider, generation = verify(args.verify_log.read_text())
    except (ValueError, OSError) as error:
        parser.exit(1, f"Mup pending failure proof rejected: {error}\n")
    print(f"Mup pending failure delivery/File reference proof: source=0x{source:016x} "
          f"provider=0x{provider:016x} generation=0x{generation:016x}")


if __name__ == "__main__":
    main()
