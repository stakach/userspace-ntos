#!/usr/bin/env python3
"""Correlate exact installer child lifetimes with same-clock loader receipts."""

import argparse
import json
from pathlib import Path
import re


_BIRTH = re.compile(r"\[pm-dynamic\] allocated hosted process .*?\bpid=(\d+)\b.*?\bpgen=(\d+)\b")
_ASSIGN = re.compile(r"\[pnp-install-batch\] child-pid/gen/file/ordinal/total=(\d+)/(\d+)/")
_ATTACH = re.compile(r"\[pnp-install-child\] child-pid/gen/owner-pid/gen/client-file/server-file=(\d+)/(\d+)/(\d+)/(\d+)/")
_ENUM = re.compile(r"\[pnp-install-enum-open\] child-pid/gen/server-file/ordinal/status=(\d+)/(\d+)/[^/]+/(\d+)/(\S+)")
_TERMINAL = re.compile(r"\[pnp-install-batch\] child-terminal pid/gen/server-file/client-file/status=(\d+)/(\d+)/")
_TICK = re.compile(r"\bat_100ns=(\d+)\b")
_LOADER_PAIR = re.compile(r"nt-ntdll: snap resolved=.*?\bpid=0x([0-9a-fA-F]+)\b.*?\bqpc-start=0x([0-9a-fA-F]+)\b.*?\bqpc-end=0x([0-9a-fA-F]+)\b")
_OWNER = re.compile(r"\bowner-pid/gen=(\d+)/(\d+)\b")


def _duration_ms(first, last):
    if first is None or last is None or last < first:
        return None
    return (last - first) / 10_000


def parse_installer_phases(lines, max_rows=512):
    """Return bounded rows; assign PID-only loader markers only to one exact lifetime."""
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    rows = {}
    loader = []
    overflow = 0
    for line in lines:
        tick_match = _TICK.search(line)
        tick = int(tick_match.group(1)) if tick_match else None
        birth = _BIRTH.search(line)
        if birth and tick is not None:
            key = (int(birth.group(1)), int(birth.group(2)))
            if key not in rows:
                if len(rows) == max_rows:
                    overflow += 1
                    continue
                rows[key] = {
                    "pid": key[0], "generation": key[1], "birth_100ns": tick,
                    "assignment_100ns": None, "attach_100ns": None,
                    "owner_pid": None, "owner_generation": None,
                    "installer_observed": False,
                    "loader_start_100ns": None, "loader_end_100ns": None,
                    "enum_open_100ns": None, "terminal_100ns": None,
                    "invalid": [],
                }
            else:
                rows[key]["invalid"].append("duplicate-birth")
            continue
        for pattern, field in ((_ASSIGN, "assignment_100ns"),
                               (_ATTACH, "attach_100ns"),
                               (_ENUM, "enum_open_100ns"),
                               (_TERMINAL, "terminal_100ns")):
            match = pattern.search(line)
            if match is None:
                continue
            if field == "enum_open_100ns" and (
                int(match.group(3)) != 1 or int(match.group(4).replace("0x", ""), 16) != 0
            ):
                break
            key = (int(match.group(1)), int(match.group(2)))
            row = rows.get(key)
            if row is not None:
                row["installer_observed"] = True
            if row is not None and tick is not None:
                owner_identity = None
                if field == "assignment_100ns":
                    owner = _OWNER.search(line)
                    if owner is not None:
                        owner_identity = (int(owner.group(1)), int(owner.group(2)))
                elif field == "attach_100ns":
                    owner_identity = (int(match.group(3)), int(match.group(4)))
                if owner_identity is not None and "owner-conflict" not in row["invalid"]:
                    previous_owner = (row["owner_pid"], row["owner_generation"])
                    if previous_owner[0] is not None and previous_owner != owner_identity:
                        row["owner_pid"] = None
                        row["owner_generation"] = None
                        row["invalid"].append("owner-conflict")
                    else:
                        row["owner_pid"], row["owner_generation"] = owner_identity
                prior = row[field]
                if prior is None:
                    row[field] = tick
                elif prior != tick:
                    row["invalid"].append("duplicate-" + field.removesuffix("_100ns"))
            break
        match = _LOADER_PAIR.search(line)
        if match is not None:
            if len(loader) < max_rows * 2:
                loader.append(tuple(int(value, 16) for value in match.groups()))
            else:
                overflow += 1

    by_pid = {}
    for row in rows.values():
        terminal = row["terminal_100ns"]
        if terminal is not None and terminal < row["birth_100ns"]:
            row["terminal_100ns"] = None
            row["invalid"].append("nonmonotonic-terminal")
        for field in ("attach_100ns", "assignment_100ns", "enum_open_100ns"):
            value = row[field]
            if value is not None and (value < row["birth_100ns"] or
                                      (row["terminal_100ns"] is not None
                                       and value > row["terminal_100ns"])):
                row[field] = None
                row["invalid"].append("outside-lifetime-" + field.removesuffix("_100ns"))
        by_pid.setdefault(row["pid"], []).append(row)
    for pid, start, end in loader:
        candidates = [row for row in by_pid.get(pid, ())
                      if not any(reason in row["invalid"] for reason in
                                 ("duplicate-birth", "duplicate-terminal",
                                  "nonmonotonic-terminal"))
                      and row["terminal_100ns"] is not None
                      and row["birth_100ns"] <= start
                      and start <= row["terminal_100ns"]]
        if len(candidates) != 1:
            continue
        row = candidates[0]
        if end < start or end > row["terminal_100ns"]:
            row["invalid"].append("nonmonotonic-loader" if end < start
                                  else "loader-outside-lifetime")
            continue
        if "duplicate-loader" in row["invalid"]:
            continue
        if row["loader_start_100ns"] is None and row["loader_end_100ns"] is None:
            row["loader_start_100ns"] = start
            row["loader_end_100ns"] = end
        else:
            row["loader_start_100ns"] = None
            row["loader_end_100ns"] = None
            row["invalid"].append("duplicate-loader")

    for row in rows.values():
        if overflow:
            # A dropped birth or loader pair may hide PID reuse or a duplicate marker.
            row["loader_start_100ns"] = None
            row["loader_end_100ns"] = None
            row["invalid"].append("truncated")
        ordered = ("birth_100ns", "loader_start_100ns", "loader_end_100ns",
                   "enum_open_100ns", "terminal_100ns")
        last = row["birth_100ns"]
        for field in ordered[1:]:
            value = row[field]
            if value is not None and value < last:
                row["invalid"].append("nonmonotonic-loader" if field.startswith("loader_")
                                      else "nonmonotonic-" + field.removesuffix("_100ns"))
                row[field] = None
            elif value is not None:
                last = value
        row["loader_ms"] = _duration_ms(row["loader_start_100ns"], row["loader_end_100ns"])
        row["birth_to_loader_ms"] = _duration_ms(row["birth_100ns"], row["loader_start_100ns"])
        row["loader_to_enum_ms"] = _duration_ms(row["loader_end_100ns"], row["enum_open_100ns"])
        row["enum_to_terminal_ms"] = _duration_ms(row["enum_open_100ns"], row["terminal_100ns"])
    return {"rows": sorted(rows.values(), key=lambda row: (row["birth_100ns"], row["pid"])),
            "overflow": overflow}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", type=Path)
    parser.add_argument("--max-rows", type=int, default=512)
    parser.add_argument("--installer-only", action="store_true")
    args = parser.parse_args()
    with args.serial.open(errors="replace") as serial:
        result = parse_installer_phases(serial, max_rows=args.max_rows)
    if args.installer_only:
        result["rows"] = [row for row in result["rows"]
                          if row["installer_observed"]]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
