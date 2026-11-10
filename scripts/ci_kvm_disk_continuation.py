#!/usr/bin/env python3
"""Transfer one stopped KVM boot disk between exact-source workflow runs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
DISK = ROOT / "rust-micro/.tmp/disk.img"
BACKUP = ROOT / "rust-micro/.tmp/disk.generated-before-resume.img"
FAILED = ROOT / "rust-micro/.tmp/disk.resumed-failed.img"
OUT = ROOT / "native-kvm-continuation-out"
IN = ROOT / "native-kvm-continuation-in"
RECEIPT = ROOT / "native-kvm-continuation-receipt.json"
ROLLBACK_MARKER = ROOT / "native-kvm-continuation-rolled-back"
WORKFLOW = ".github/workflows/native-kvm-smoke.yml"
MAX_DISK_BYTES = 2 * 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ContinuationError(RuntimeError):
    pass


def require_regular(path: Path, maximum: int | None = None) -> int:
    try:
        info = path.lstat()
    except OSError as error:
        raise ContinuationError(f"cannot inspect file: {path}") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
        raise ContinuationError(f"not a regular file: {path}")
    if maximum is not None and info.st_size > maximum:
        raise ContinuationError(f"file too large: {path}")
    return info.st_size


def digest(path: Path) -> str:
    require_regular(path)
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def expected_build() -> dict:
    head = git("rev-parse", "HEAD")
    if head != os.environ["GITHUB_SHA"]:
        raise ContinuationError("checkout is not the workflow event head")
    size = require_regular(DISK, MAX_DISK_BYTES)
    if size == 0:
        raise ContinuationError("generated boot disk is empty")
    base = digest(DISK)
    recorded = (ROOT / "native-kvm-image.sha256").read_text().split()[0]
    if not SHA256.fullmatch(recorded) or recorded != base:
        raise ContinuationError("generated boot disk differs from build receipt")
    return {
        "head_sha": head,
        "ref": os.environ["GITHUB_REF"],
        "repo": os.environ["GITHUB_REPOSITORY"],
        "workflow": WORKFLOW,
        "submodule_sha": git("rev-parse", "HEAD", cwd=ROOT / "rust-micro"),
        "libernt_manifest_sha256": digest(ROOT / "rust-micro/vendor/libernt/manifest.txt"),
        "base_disk_sha256": base,
        "disk_size_bytes": size,
        "rootserver_sha256": digest(ROOT / "rust-micro/.tmp/rootserver.elf"),
        "kernel_sha256": digest(ROOT / "rust-micro/target/mykernel-x86/release/mykernel-rust"),
        "ntdll_sha256": digest(ROOT / ".tmp/nt-ntdll.dll"),
        "image_profile": (ROOT / "rust-micro/.tmp/image-profile").read_text().strip(),
    }


def no_qemu_owner() -> None:
    for task in Path("/proc").iterdir():
        if not task.name.isdecimal():
            continue
        try:
            if (task / "stat").read_text().split(") ", 1)[1][:1] == "Z":
                continue
            command = (task / "comm").read_text().strip()
        except (OSError, IndexError):
            continue
        # Linux comm is limited to 15 bytes, so the x86 suffix is truncated.
        if command.startswith("qemu-system") or command == "run_specs.sh":
            raise ContinuationError(f"boot owner still running: pid {task.name}")


def stopped() -> None:
    marker = ROOT / "native-kvm-qemu-stopped"
    if marker.read_text() != "QEMU process group stopped and reaped\n":
        raise ContinuationError("QEMU stop receipt is missing or invalid")
    no_qemu_owner()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_manifest(path: Path) -> dict:
    require_regular(path, 64 * 1024)
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ContinuationError("unsupported continuation manifest")
    return value


def api_run(run_id: int, attempt: int, token: str, repo: str) -> dict:
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ContinuationError("invalid Actions API authority")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def verify_run(run: dict, run_id: int, attempt: int, current: dict) -> None:
    expected = {
        "id": run_id, "run_attempt": attempt, "status": "completed",
        "conclusion": "success", "event": "workflow_dispatch",
        "head_sha": current["head_sha"],
    }
    for key, value in expected.items():
        if run.get(key) != value:
            raise ContinuationError(f"source run {key} mismatch")
    if (run.get("repository") or {}).get("full_name") != current["repo"] \
        or (run.get("head_repository") or {}).get("full_name") != current["repo"]:
        raise ContinuationError("source run belongs to another repository")
    if run.get("path", "").split("@", 1)[0] != WORKFLOW:
        raise ContinuationError("source run used another workflow")
    if current["ref"] != f"refs/heads/{run.get('head_branch')}":
        raise ContinuationError("source run branch differs from this exact ref")
    if run_id == int(os.environ["GITHUB_RUN_ID"]):
        raise ContinuationError("cannot resume this same workflow run")


def verify_manifest(value: dict, run_id: int, attempt: int, current: dict) -> None:
    expected = {
        "source_run_id": run_id, "source_run_attempt": attempt,
        "source_head_sha": current["head_sha"], "source_ref": current["ref"],
        "source_repo": current["repo"], "workflow": WORKFLOW,
    }
    expected.update({key: current[key] for key in (
        "submodule_sha", "libernt_manifest_sha256",
        "disk_size_bytes", "rootserver_sha256", "kernel_sha256",
        "ntdll_sha256", "image_profile",
    )})
    for key, target in expected.items():
        if value.get(key) != target:
            raise ContinuationError(f"continuation {key} differs from current build")
    if not isinstance(value.get("disk_sha256"), str) \
        or not SHA256.fullmatch(value["disk_sha256"]):
        raise ContinuationError("continuation disk digest is invalid")
    # Simpleboot seeds GUIDs and FAT timestamps at image creation. Each run checks
    # its own generated baseline receipt; byte equality across builds is not identity.
    if not isinstance(value.get("base_disk_sha256"), str) \
        or not SHA256.fullmatch(value["base_disk_sha256"]):
        raise ContinuationError("source generated-disk digest is invalid")
    if value.get("qemu_stopped") is not True:
        raise ContinuationError("source QEMU stop receipt absent")


def publish(boot_runs: int, boot_seconds: int) -> None:
    stopped()
    build = expected_build_after_boot()
    final_hash_path = ROOT / f"native-kvm-image-after-boot{boot_runs}.sha256"
    recorded = final_hash_path.read_text().split()[0]
    final = digest(DISK)
    if recorded != final:
        raise ContinuationError("boot disk differs from final boot receipt")
    if OUT.exists():
        raise ContinuationError("continuation output already exists")
    OUT.mkdir()
    try:
        os.link(DISK, OUT / "disk.img")
        manifest = {
            "schema": 1, "source_run_id": int(os.environ["GITHUB_RUN_ID"]),
            "source_run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "source_head_sha": build.pop("head_sha"),
            "source_ref": build.pop("ref"), "source_repo": build.pop("repo"),
            "workflow": WORKFLOW, **build,
            "disk_sha256": final, "qemu_stopped": True,
            "boot_runs": boot_runs, "boot_seconds": boot_seconds,
            "qemu_version": subprocess.check_output(
                ["qemu-system-x86_64", "--version"], text=True).splitlines()[0],
        }
        write_json(OUT / "manifest.json", manifest)
    except BaseException:
        (OUT / "disk.img").unlink(missing_ok=True)
        (OUT / "manifest.json").unlink(missing_ok=True)
        OUT.rmdir()
        raise


def expected_build_after_boot() -> dict:
    # The generated-disk receipt was written before boot; only the other build outputs
    # remain available after the writable image has advanced.
    current_disk = DISK
    original = ROOT / "native-kvm-image.sha256"
    size = require_regular(current_disk, MAX_DISK_BYTES)
    recorded = original.read_text().split()[0]
    if size == 0 or not SHA256.fullmatch(recorded):
        raise ContinuationError("invalid original build receipt")
    head = git("rev-parse", "HEAD")
    if head != os.environ["GITHUB_SHA"]:
        raise ContinuationError("checkout is not the workflow event head")
    return {
        "head_sha": head, "ref": os.environ["GITHUB_REF"],
        "repo": os.environ["GITHUB_REPOSITORY"],
        "submodule_sha": git("rev-parse", "HEAD", cwd=ROOT / "rust-micro"),
        "libernt_manifest_sha256": digest(ROOT / "rust-micro/vendor/libernt/manifest.txt"),
        "base_disk_sha256": recorded, "disk_size_bytes": size,
        "rootserver_sha256": digest(ROOT / "rust-micro/.tmp/rootserver.elf"),
        "kernel_sha256": digest(ROOT / "rust-micro/target/mykernel-x86/release/mykernel-rust"),
        "ntdll_sha256": digest(ROOT / ".tmp/nt-ntdll.dll"),
        "image_profile": (ROOT / "rust-micro/.tmp/image-profile").read_text().strip(),
    }


def restore(run_id: int, attempt: int, token: str) -> None:
    current = expected_build()
    verify_run(api_run(run_id, attempt, token, current["repo"]), run_id, attempt, current)
    if not stat.S_ISDIR(IN.lstat().st_mode):
        raise ContinuationError("continuation input is not a real directory")
    manifest = read_manifest(IN / "manifest.json")
    verify_manifest(manifest, run_id, attempt, current)
    incoming = IN / "disk.img"
    if require_regular(incoming, MAX_DISK_BYTES) != current["disk_size_bytes"]:
        raise ContinuationError("continuation disk length differs from generated disk")
    if digest(incoming) != manifest["disk_sha256"]:
        raise ContinuationError("continuation disk SHA-256 mismatch")
    no_qemu_owner()
    if BACKUP.exists() or RECEIPT.exists() or FAILED.exists():
        raise ContinuationError("another continuation or rollback is present")
    os.replace(DISK, BACKUP)
    try:
        os.replace(incoming, DISK)
        write_json(RECEIPT, {
            "source_run_id": run_id, "source_run_attempt": attempt,
            "base_disk_sha256": current["base_disk_sha256"],
            "resumed_disk_sha256": manifest["disk_sha256"],
        })
    except BaseException:
        os.replace(BACKUP, DISK)
        raise


def rollback() -> None:
    stopped()
    receipt = read_json_receipt()
    if digest(BACKUP) != receipt["base_disk_sha256"]:
        raise ContinuationError("rollback disk does not match generated build")
    no_qemu_owner()
    if FAILED.exists():
        raise ContinuationError("failed resumed disk already retained")
    os.replace(DISK, FAILED)
    try:
        os.replace(BACKUP, DISK)
    except BaseException:
        os.replace(FAILED, DISK)
        raise
    ROLLBACK_MARKER.write_text("resumed boot failed; generated disk restored\n")


def read_json_receipt() -> dict:
    require_regular(RECEIPT, 4096)
    value = json.loads(RECEIPT.read_text())
    if not isinstance(value, dict) or not SHA256.fullmatch(value.get("base_disk_sha256", "")):
        raise ContinuationError("invalid local continuation receipt")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    source = subcommands.add_parser("check-run")
    source.add_argument("--run-id", type=int, required=True)
    source.add_argument("--attempt", type=int, required=True)
    publish_command = subcommands.add_parser("publish")
    publish_command.add_argument("--boot-runs", type=int, choices=(1, 2), required=True)
    publish_command.add_argument("--boot-seconds", type=int, required=True)
    restore_command = subcommands.add_parser("restore")
    restore_command.add_argument("--run-id", type=int, required=True)
    restore_command.add_argument("--attempt", type=int, required=True)
    subcommands.add_parser("rollback")
    args = parser.parse_args()
    if args.command in ("check-run", "restore"):
        if args.run_id <= 0 or args.attempt <= 0:
            parser.error("run ID and attempt must be positive")
        token = os.environ.get("GITHUB_TOKEN", "")
        if args.command == "check-run":
            current = {"head_sha": git("rev-parse", "HEAD"),
                       "ref": os.environ["GITHUB_REF"],
                       "repo": os.environ["GITHUB_REPOSITORY"]}
            if current["head_sha"] != os.environ["GITHUB_SHA"]:
                raise ContinuationError("checkout is not the workflow event head")
            verify_run(api_run(args.run_id, args.attempt, token, current["repo"]),
                       args.run_id, args.attempt, current)
        else:
            restore(args.run_id, args.attempt, token)
    elif args.command == "publish":
        if not 1 <= args.boot_seconds <= 3600:
            parser.error("boot seconds must be within the bounded QEMU runtime")
        publish(args.boot_runs, args.boot_seconds)
    else:
        rollback()


if __name__ == "__main__":
    main()
