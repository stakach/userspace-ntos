#!/usr/bin/env python3
"""Require genuine private-font execution and at least one exact file-backed view retirement.

This is not proof that every font view retired, nor proof of a font pathname or desktop.
"""
import argparse
import re
from pathlib import Path

TERMINAL = re.compile(
    r"^\[process-terminal-committed\] pi=(\d+) pid=(\d+) generation=(\d+) "
    r"exit-status=0x([0-9a-f]{8}) signaled=1$"
)
DELETED = re.compile(r"^\[process-delete\] retired pi=(\d+) pid=(\d+) generation=(\d+) threads=(\d+)$")
IDENTITY = (
    r"pointer=(?P<pointer>0x[0-9a-f]{16}) native-generation=(?P<native_generation>[1-9]\d*) "
    r"view-generation=(?P<view_generation>[1-9]\d*) provider-domain=(?P<provider_domain>[1-9]\d*) "
    r"provider-generation=(?P<provider_generation>[1-9]\d*) base=(?P<base>0x[0-9a-f]{16}) "
    r"section-index=(?P<section_index>\d+) section-generation=(?P<section_generation>[1-9]\d*) "
    r"backing-kind=(?P<backing_kind>[234]) file-present=1 "
    r"file-mount=(?P<file_mount>[1-9]\d*) file-id=(?P<file_id>[1-9]\d*) "
    r"initiator=hosted initiator-pi=(?P<initiator_pi>\d+) "
    r"initiator-pid=(?P<initiator_pid>[1-9]\d*) initiator-generation=(?P<initiator_generation>[1-9]\d*) "
    r"initiator-tid=(?P<initiator_tid>[1-9]\d*) initiator-thread-generation=(?P<initiator_thread_generation>[1-9]\d*)"
)
IDENTITY_FIELDS = tuple(re.compile(IDENTITY).groupindex)
MAPPED = re.compile(r"^\[kernel-section-map\] " + IDENTITY + r" bytes=([1-9]\d*) pages=([1-9]\d*)$")
UNMAPPED = re.compile(r"^\[kernel-section-unmap-retired\] " + IDENTITY + r" remaining-refs=0$")
CLEANUP = re.compile(
    r"^\[kernel-section-cleanup-result\] op=unmap target=(?P<cleanup_target>0x[0-9a-f]{16}) "
    r"provider-domain=(?P<cleanup_domain>[1-9]\d*) provider-generation=(?P<cleanup_provider_generation>[1-9]\d*) "
    r"caller=(?:logical|kernel) pid=(?P<cleanup_pid>[1-9]\d*) tid=[1-9]\d* "
    r"thread-generation=[1-9]\d* process=hosted process-pi=(?P<cleanup_pi>\d+) "
    r"process-generation=(?P<cleanup_generation>[1-9]\d*) canonical-current=1 process-signaled=1 "
    r"status=0x00000000 return-value=0 retired-view " + IDENTITY + r"$"
)


def view_identity(match):
    return tuple(match[name] for name in IDENTITY_FIELDS)


def verify(text):
    lines = [re.sub(r"^\[smss\] ", "", line) for line in text.splitlines()]
    if any("[provider-bugcheck] terminal" in line or
           re.search(r"\[font-(?:setup|acceptance)\] (?:FAIL|TERMINATE-RETURNED)", line)
           for line in lines):
        raise ValueError("native failure")

    def unique(pattern):
        matches = [(index, match) for index, line in enumerate(lines)
                   if (match := re.fullmatch(pattern, line))]
        if len(matches) != 1:
            raise ValueError(f"missing or duplicate {pattern}")
        return matches[0]

    def execution(name, passed):
        prefix = rf"\[{name}\] "
        query, _ = unique(prefix + r"PID-QUERY actual=0x00000000 expected=0x00000000")
        begin, identity = unique(prefix + r"BEGIN pid=([1-9]\d*)")
        success, _ = unique(prefix + passed)
        requested, _ = unique(prefix + r"EXIT-REQUEST status=0x00000000")
        pid = int(identity[1])
        terminals = [(index, match) for index, line in enumerate(lines)
                     if (match := TERMINAL.fullmatch(line)) and int(match[2]) == pid]
        if len(terminals) != 1:
            raise ValueError("missing or duplicate canonical process termination")
        terminal, match = terminals[0]
        pi, _, generation = map(int, match.groups()[:3])
        if match[4] != "00000000" or generation == 0:
            raise ValueError("unsuccessful canonical process termination")
        deletions = [index for index, line in enumerate(lines)
                     if (row := DELETED.fullmatch(line)) and
                     tuple(map(int, row.groups()[:3])) == (pi, pid, generation)]
        if len(deletions) != 1 or not query < begin < success < requested < terminal < deletions[0]:
            raise ValueError("missing or misordered exact process resource retirement")
        return begin, success, terminal, deletions[0], pid, generation, pi

    setup = execution("font-setup", r"PASS RUN-REGISTERED")
    for stage in ("CREATE-RUN", "SET-RUN", "READBACK-RUN", "CLOSE-RUN"):
        index, _ = unique(rf"\[font-setup\] {stage} actual=0x00000000 expected=0x00000000")
        if not setup[0] < index < setup[1]:
            raise ValueError("setup registry operation outside fixture execution")
    font = execution("font-acceptance", r"PASS PRIVATE-FONT-LOADED")
    added, _ = unique(r"\[font-acceptance\] ADDED fonts=([1-9]\d*) flags=0x00000010")
    if setup[2] >= font[0] or not font[0] < added < font[1] or setup[4] == font[4]:
        raise ValueError("missing independent genuine font execution")

    maps = [view_identity(match) for index, line in enumerate(lines)
            if font[0] < index < added and (match := MAPPED.fullmatch(line)) and
            tuple(int(match[name]) for name in
                  ("initiator_pi", "initiator_pid", "initiator_generation")) ==
            (font[6], font[4], font[5])]
    all_maps = [view_identity(match) for line in lines if (match := MAPPED.fullmatch(line))]
    if any(all_maps.count(identity) != 1 for identity in maps):
        raise ValueError("duplicate exact view publication")
    proven = []
    for identity in maps:
        retired = [index for index, line in enumerate(lines)
                   if (match := UNMAPPED.fullmatch(line)) and view_identity(match) == identity]
        if not retired:
            continue
        if len(retired) != 1 or not font[2] < retired[0] < font[3]:
            raise ValueError("duplicate or premature exact view retirement")
        results = [index for index, line in enumerate(lines)
                   if (match := CLEANUP.fullmatch(line)) and
                   view_identity(match) == identity and
                   (match["cleanup_target"], match["cleanup_domain"], match["cleanup_provider_generation"]) ==
                   (match["base"], match["provider_domain"], match["provider_generation"]) and
                   tuple(int(match[name]) for name in
                         ("cleanup_pi", "cleanup_pid", "cleanup_generation")) ==
                   (font[6], font[4], font[5])]
        if len(results) != 1 or not retired[0] < results[0] < font[3]:
            raise ValueError("missing successful terminal-owner cleanup result")
        proven.append(identity)
    if not proven:
        raise ValueError("no exact font view retired after canonical termination")
    return font[4], font[5], len(proven)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        pid, generation, views = verify(args.log.read_text())
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(1, f"FAIL native font cleanup: {error}\n")
    print(f"PASS native font cleanup: pid={pid} generation={generation} views={views}; desktop not verified")


if __name__ == "__main__":
    main()
