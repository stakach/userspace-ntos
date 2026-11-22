#!/usr/bin/env python3
"""Formatting and clippy gate for the crates listed in scripts/ci_lint_scope.txt (#32).

A crate joins the scope once its formatting and clippy debt is resolved; the gate then keeps
it clean. Crates outside the scope are still compiled as dependencies, but their findings do
not fail the gate. Crate specs run separately, so no lint setting here can hide a test failure.
"""

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SCOPE = ROOT / "scripts" / "ci_lint_scope.txt"


def load_scope(path=SCOPE):
    """Package names, one per line; blank lines and `#` comments are ignored."""
    names = []
    for line in path.read_text().splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            names.append(name)
    if len(set(names)) != len(names):
        raise ValueError("the lint scope lists a package twice")
    return names


def workspace_packages():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], cwd=ROOT))
    return {package["name"]: package["id"] for package in metadata["packages"]}


def scoped_findings(messages, package_ids):
    """Rendered clippy/rustc warnings and errors that belong to a package in scope."""
    findings = []
    for line in messages:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-message":
            continue
        if message.get("package_id") not in package_ids:
            continue
        diagnostic = message.get("message", {})
        if diagnostic.get("level") in ("warning", "error"):
            findings.append(diagnostic.get("rendered") or diagnostic.get("message", ""))
    return findings


def main():
    scope = load_scope()
    packages = workspace_packages()
    unknown = sorted(set(scope) - set(packages))
    if unknown:
        raise SystemExit(f"lint scope names packages outside the workspace: {', '.join(unknown)}")
    selected = [argument for name in scope for argument in ("-p", name)]
    formatted = subprocess.run(["cargo", "fmt", "--check", *selected], cwd=ROOT)
    clippy = subprocess.run(
        # `--no-deps` lints only the scoped packages; their workspace dependencies still build.
        ["cargo", "clippy", "--locked", "--all-targets", "--message-format", "json", *selected,
         "--", "--no-deps", "-D", "warnings"],
        cwd=ROOT, stdout=subprocess.PIPE, text=True)
    findings = scoped_findings(clippy.stdout.splitlines(), {packages[name] for name in scope})
    for finding in findings:
        print(finding, end="" if finding.endswith("\n") else "\n")
    failed = []
    if formatted.returncode != 0:
        failed.append("cargo fmt --check")
    if clippy.returncode != 0:
        failed.append(f"cargo clippy exited {clippy.returncode}")
    if findings:
        failed.append(f"{len(findings)} clippy findings in scoped crates")
    if failed:
        raise SystemExit("scoped lint gate failed: " + "; ".join(failed))
    print(f"scoped lint gate passed for {len(scope)} crates")


if __name__ == "__main__":
    sys.exit(main())
