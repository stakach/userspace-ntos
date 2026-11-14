#!/usr/bin/env python3
"""Name the allocating sites in an executive boot log.

The executive prints `site=0x...,0x...` return-address chains on `[alloc-large]`,
`[alloc-oom]` and `[heap-owner]` lines. This resolves each address against the
symbol table of the rootserver ELF that produced the log (the KVM smoke run
uploads it as `rust-micro/.tmp/rootserver.elf`) and prints the matching lines
with `function+offset` chains, innermost caller first.

    scripts/symbolize_alloc_sites.py rootserver.elf boot.log [--all]

By default only the last census (`[heap-owners]` and its `[heap-owner]` rows),
every `[alloc-large]` and every `[alloc-oom]` are printed; `--all` prints every
census. Names are demangled when `rustfilt` is installed.
"""
import bisect
import re
import shutil
import subprocess
import sys

SITE = re.compile(r"site=((?:0x[0-9a-f]+,?)+)")


def load_symbols(elf):
    """Sorted (address, name) for the ELF's text symbols."""
    listing = subprocess.run(
        ["nm", "-n", elf], check=True, capture_output=True, text=True
    ).stdout
    symbols = []
    for line in listing.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[1] in "tTwW":
            symbols.append((int(parts[0], 16), parts[2]))
    symbols.sort()
    names = [name for _, name in symbols]
    if shutil.which("rustfilt"):
        names = subprocess.run(
            ["rustfilt"], input="\n".join(names), check=True, capture_output=True, text=True
        ).stdout.splitlines()
    return [address for address, _ in symbols], names


def resolve(address, addresses, names):
    index = bisect.bisect_right(addresses, address) - 1
    if index < 0:
        return hex(address)
    return f"{names[index]}+{address - addresses[index]:#x}"


def symbolize(line, addresses, names):
    def replace(match):
        chain = [int(word, 16) for word in match.group(1).split(",") if word]
        return "site=" + " < ".join(resolve(address, addresses, names) for address in chain)

    return SITE.sub(replace, line)


def select(lines, every_census):
    """Lines worth printing: large/failed allocations and the chosen censuses."""
    last_census = max(
        (index for index, line in enumerate(lines) if line.startswith("[heap-owners]")),
        default=None,
    )
    census_start = None
    for index, line in enumerate(lines):
        if line.startswith("[heap-owners]"):
            census_start = index
        if line.startswith(("[alloc-large]", "[alloc-oom]")):
            yield line
        elif line.startswith(("[heap-owners]", "[heap-owner]")) and (
            every_census or census_start == last_census
        ):
            yield line


def main(argv):
    arguments = [argument for argument in argv[1:] if argument != "--all"]
    if len(arguments) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    addresses, names = load_symbols(arguments[0])
    with open(arguments[1], errors="replace") as log:
        lines = log.read().splitlines()
    for line in select(lines, "--all" in argv):
        print(symbolize(line, addresses, names))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
