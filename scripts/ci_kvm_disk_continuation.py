#!/usr/bin/env python3
"""Transfer stopped KVM boot disks by exact continuation or explicit code migration."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parent.parent
DISK = ROOT / "rust-micro/.tmp/disk.img"
BACKUP = ROOT / "rust-micro/.tmp/disk.generated-before-resume.img"
FAILED = ROOT / "rust-micro/.tmp/disk.resumed-failed.img"
OUT = ROOT / "native-kvm-continuation-out"
IN = ROOT / "native-kvm-continuation-in"
RECEIPT = ROOT / "native-kvm-continuation-receipt.json"
ROLLBACK_MARKER = ROOT / "native-kvm-continuation-rolled-back"
MIGRATION_CANDIDATE = DISK.with_name("disk.migration-candidate.img")
WORKFLOW = ".github/workflows/native-kvm-smoke.yml"
MAX_DISK_BYTES = 2 * 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
MIGRATED_FILES = {
    "kernel": "kernel",
    "initrd.tar": "initrd.tar",
    "Windows/system32/ntdll.dll": "Windows/system32/ntdll.dll",
    "IMPORTS.BIN": "IMPORTS.BIN",
}
RELEASED_ACPI = "Windows/system32/drivers/acpi.sys"


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


def source_is_ancestor(source_head: str, target_head: str) -> bool:
    if not COMMIT.fullmatch(source_head) or not COMMIT.fullmatch(target_head):
        return False
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_head, target_head],
        cwd=ROOT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def verify_migration_run(run: dict, run_id: int, attempt: int, current: dict) -> None:
    expected = {
        "id": run_id, "run_attempt": attempt, "status": "completed",
        "conclusion": "success", "event": "workflow_dispatch",
    }
    for key, value in expected.items():
        if run.get(key) != value:
            raise ContinuationError(f"source run {key} mismatch")
    source_head = run.get("head_sha")
    if not isinstance(source_head, str) or source_head == current["head_sha"] \
            or not source_is_ancestor(source_head, current["head_sha"]):
        raise ContinuationError("migration source is not an earlier ancestor of this head")
    if (run.get("repository") or {}).get("full_name") != current["repo"] \
            or (run.get("head_repository") or {}).get("full_name") != current["repo"]:
        raise ContinuationError("source run belongs to another repository")
    if run.get("path", "").split("@", 1)[0] != WORKFLOW:
        raise ContinuationError("source run used another workflow")
    if current["ref"] != f"refs/heads/{run.get('head_branch')}":
        raise ContinuationError("source run branch differs from this ref")
    if run_id == int(os.environ["GITHUB_RUN_ID"]):
        raise ContinuationError("cannot migrate this same workflow run")


def verify_migration_manifest(value: dict, run_id: int, attempt: int,
                              current: dict, run: dict) -> None:
    # Other profiles can stage native fixtures and a different initial hive. Their
    # code/data migration set needs its own explicit contract.
    if current["image_profile"] != "production":
        raise ContinuationError("cross-commit migration is limited to production images")
    expected = {
        "source_run_id": run_id, "source_run_attempt": attempt,
        "source_head_sha": run["head_sha"], "source_ref": current["ref"],
        "source_repo": current["repo"], "workflow": WORKFLOW,
    }
    expected.update({key: current[key] for key in (
        "submodule_sha", "libernt_manifest_sha256", "disk_size_bytes", "image_profile",
    )})
    for key, target in expected.items():
        if value.get(key) != target:
            raise ContinuationError(f"migration {key} differs from source or current build")
    for key in ("disk_sha256", "base_disk_sha256", "kernel_sha256",
                "rootserver_sha256", "ntdll_sha256"):
        if not isinstance(value.get(key), str) or not SHA256.fullmatch(value[key]):
            raise ContinuationError(f"migration {key} is invalid")
    if value.get("qemu_stopped") is not True:
        raise ContinuationError("source QEMU stop receipt absent")


def esp_geometry(image: Path) -> tuple[int, int]:
    size = require_regular(image, MAX_DISK_BYTES)
    with image.open("rb") as disk_file:
        header = disk_file.read(1024)
        entry = disk_file.read(128)
        if header[512:520] != b"EFI PART" or len(entry) != 128:
            raise ContinuationError("disk has no expected GPT header")
        if int.from_bytes(header[584:592], "little") != 2 \
                or int.from_bytes(header[596:600], "little") != 128:
            raise ContinuationError("disk has unexpected GPT partition table")
        if uuid.UUID(bytes_le=entry[:16]) != ESP_TYPE:
            raise ContinuationError("first GPT partition is not the Simpleboot ESP")
        first = int.from_bytes(entry[32:40], "little")
        last = int.from_bytes(entry[40:48], "little")
        offset, length = first * 512, (last - first + 1) * 512
        if first < 34 or last < first or offset + length > size:
            raise ContinuationError("ESP geometry exceeds disk")
        disk_file.seek(offset)
        boot = disk_file.read(512)
        if boot[82:87] != b"FAT32" or boot[510:512] != b"\x55\xaa":
            raise ContinuationError("ESP is not the expected FAT32 filesystem")
    return offset, length


def esp_file(image: Path, offset: int, name: str) -> bytes:
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "file"
        command = ["mcopy", "-i", f"{image}@@{offset}", f"::/{name}", str(output)]
        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ContinuationError(f"cannot read ESP file {name}") from error
        require_regular(output)
        return output.read_bytes()


def replace_esp_file(image: Path, offset: int, name: str, source: Path) -> None:
    require_regular(source)
    command = ["mcopy", "-o", "-i", f"{image}@@{offset}", str(source), f"::/{name}"]
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContinuationError(f"cannot replace ESP file {name}") from error


def driver_inventory(image: Path, offset: int) -> set[str]:
    command = ["mdir", "-a", "-b", "-i", f"{image}@@{offset}",
               "::/Windows/system32/drivers"]
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, errors="surrogateescape")
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContinuationError("cannot list ESP driver directory") from error
    names = [Path(line.strip().replace("\\", "/")).name.casefold()
             for line in result.stdout.splitlines()
             if line.strip().casefold().endswith(".sys")]
    if len(names) != len(set(names)) or "acpi.sys" not in names:
        raise ContinuationError("ambiguous ESP driver inventory")
    return set(names)


def region_digest(image: Path, start: int, length: int) -> str:
    value = hashlib.sha256()
    with image.open("rb") as source:
        source.seek(start)
        while length:
            block = source.read(min(length, 1024 * 1024))
            if not block:
                raise ContinuationError("disk region ended early")
            value.update(block)
            length -= len(block)
    return value.hexdigest()


def verify_hive_provenance(manifest: dict, source: Path) -> None:
    """Preserve guest registry state only when its generated base is identified."""
    hive = ROOT / "rust-micro/.tmp/hive.dat"
    current_hash = digest(hive)
    current_offset, _ = esp_geometry(DISK)
    if hashlib.sha256(esp_file(DISK, current_offset, "SYSTEM.DAT")).hexdigest() != current_hash:
        raise ContinuationError("current image hive differs from generated hive")
    recorded = manifest.get("generated_hive_sha256")
    if recorded is not None:
        if not isinstance(recorded, str) or not SHA256.fullmatch(recorded) \
                or recorded != current_hash:
            raise ContinuationError("source and target generated hives differ")
        return
    # Older manifests omitted this digest. They migrate only if the on-disk
    # hive is still exactly the generated baseline.
    offset, _ = esp_geometry(source)
    if hashlib.sha256(esp_file(source, offset, "SYSTEM.DAT")).hexdigest() != current_hash:
        raise ContinuationError("older source has an advanced hive without base provenance")


def patch_migration_esp(candidate: Path, source: Path, current: dict) -> dict:
    source_geometry = esp_geometry(source)
    if esp_geometry(candidate) != source_geometry or esp_geometry(DISK) != source_geometry:
        raise ContinuationError("migration ESP geometry differs from current image")
    offset, length = source_geometry
    staged = ROOT / "rust-micro/.tmp/simpleboot-esp"
    manifest = (ROOT / "rust-micro/vendor/libernt/manifest.txt").read_text()
    acpi_hash = next((line.split("=", 1)[1] for line in manifest.splitlines()
                      if line.startswith("acpi_sha256=")), "")
    if not SHA256.fullmatch(acpi_hash):
        raise ContinuationError("pinned acpi digest is missing")
    acpi_source = esp_file(source, offset, RELEASED_ACPI)
    if hashlib.sha256(acpi_source).hexdigest() != acpi_hash:
        raise ContinuationError("source disk changed the released acpi.sys")
    if hashlib.sha256(esp_file(DISK, offset, RELEASED_ACPI)).hexdigest() != acpi_hash:
        raise ContinuationError("current image changed the released acpi.sys")
    source_drivers = driver_inventory(source, offset)
    if source_drivers != driver_inventory(DISK, offset):
        raise ContinuationError("source driver inventory differs from current image")
    # These production overlays are left on the installed disk. Refuse a code
    # migration if one changed rather than silently booting an old companion DLL
    # or native test driver with the new rootserver.
    stable_overlays = ["simpleboot.cfg", "Windows/system32/nt-seh-linkage.dll"]
    release_tree = ROOT / "rust-micro/.tmp/libernt/tree"
    driver_stage = staged / "Windows/system32/drivers"
    if driver_stage.is_dir():
        for driver in driver_stage.glob("*.sys"):
            relative = driver.relative_to(staged)
            release_driver = release_tree / relative
            if not release_driver.is_file() or driver.read_bytes() != release_driver.read_bytes():
                stable_overlays.append(relative.as_posix())
    for name in stable_overlays:
        staged_file = staged / name
        if staged_file.is_file():
            expected = staged_file.read_bytes()
            if esp_file(DISK, offset, name) != expected or esp_file(source, offset, name) != expected:
                raise ContinuationError(f"unmigrated production overlay {name} differs")
        elif name != "Windows/system32/nt-seh-linkage.dll":
            raise ContinuationError(f"production overlay {name} is missing")
    changes = {}
    for name, stage_name in MIGRATED_FILES.items():
        staged_file = staged / stage_name
        require_regular(staged_file)
        target_bytes = staged_file.read_bytes()
        if not target_bytes or esp_file(DISK, offset, name) != target_bytes:
            raise ContinuationError(f"current staged {name} differs from generated image")
        source_bytes = esp_file(source, offset, name)
        changes[name] = {
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "target_sha256": hashlib.sha256(target_bytes).hexdigest(),
        }
        replace_esp_file(candidate, offset, name, staged_file)
        if esp_file(candidate, offset, name) != target_bytes:
            raise ContinuationError(f"migrated {name} failed ESP readback")
    if hashlib.sha256(esp_file(candidate, offset, RELEASED_ACPI)).hexdigest() != acpi_hash:
        raise ContinuationError("migration changed released acpi.sys")
    if driver_inventory(candidate, offset) != source_drivers:
        raise ContinuationError("migration changed driver inventory")
    end = offset + length
    for start, count in ((0, offset), (end, current["disk_size_bytes"] - end)):
        if region_digest(source, start, count) != region_digest(candidate, start, count):
            raise ContinuationError("migration changed bytes outside the ESP")
    return changes


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
        manifest["generated_hive_sha256"] = digest(ROOT / "rust-micro/.tmp/hive.dat")
        if RECEIPT.exists():
            manifest["disk_origin"] = read_json_receipt()
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


def migrate(run_id: int, attempt: int, token: str) -> None:
    """Install a separately identified source disk with current boot code staged once."""
    current = expected_build()
    run = api_run(run_id, attempt, token, current["repo"])
    verify_migration_run(run, run_id, attempt, current)
    if not stat.S_ISDIR(IN.lstat().st_mode):
        raise ContinuationError("migration input is not a real directory")
    manifest = read_manifest(IN / "manifest.json")
    verify_migration_manifest(manifest, run_id, attempt, current, run)
    incoming = IN / "disk.img"
    if require_regular(incoming, MAX_DISK_BYTES) != current["disk_size_bytes"]:
        raise ContinuationError("source disk length differs from current generated disk")
    if digest(incoming) != manifest["disk_sha256"]:
        raise ContinuationError("source disk SHA-256 mismatch")
    verify_hive_provenance(manifest, incoming)
    no_qemu_owner()
    if any(path.exists() for path in (BACKUP, RECEIPT, FAILED, MIGRATION_CANDIDATE)):
        raise ContinuationError("another continuation, migration, or rollback is present")
    candidate = MIGRATION_CANDIDATE
    try:
        shutil.copyfile(incoming, candidate)
        changes = patch_migration_esp(candidate, incoming, current)
        if require_regular(candidate, MAX_DISK_BYTES) != current["disk_size_bytes"]:
            raise ContinuationError("migration changed disk length")
        migrated_hash = digest(candidate)
        if digest(incoming) != manifest["disk_sha256"]:
            raise ContinuationError("migration changed the source artifact")
        no_qemu_owner()
        receipt = {
            "mode": "migration", "source_run_id": run_id,
            "source_run_attempt": attempt, "source_head_sha": run["head_sha"],
            "target_head_sha": current["head_sha"],
            "source_disk_sha256": manifest["disk_sha256"],
            "base_disk_sha256": current["base_disk_sha256"],
            "resumed_disk_sha256": migrated_hash,
            "libernt_manifest_sha256": current["libernt_manifest_sha256"],
            "generated_hive_sha256": digest(ROOT / "rust-micro/.tmp/hive.dat"),
            "submodule_sha": current["submodule_sha"],
            "image_profile": current["image_profile"],
            "esp_file_changes": changes,
        }
        os.replace(DISK, BACKUP)
        try:
            os.replace(candidate, DISK)
            write_json(RECEIPT, receipt)
        except BaseException:
            if DISK.exists():
                os.replace(DISK, candidate)
            os.replace(BACKUP, DISK)
            RECEIPT.unlink(missing_ok=True)
            raise
    finally:
        candidate.unlink(missing_ok=True)


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
    migration_check = subcommands.add_parser("check-migration-run")
    migration_check.add_argument("--run-id", type=int, required=True)
    migration_check.add_argument("--attempt", type=int, required=True)
    migration_command = subcommands.add_parser("migrate")
    migration_command.add_argument("--run-id", type=int, required=True)
    migration_command.add_argument("--attempt", type=int, required=True)
    subcommands.add_parser("rollback")
    args = parser.parse_args()
    if args.command in ("check-run", "restore", "check-migration-run", "migrate"):
        if args.run_id <= 0 or args.attempt <= 0:
            parser.error("run ID and attempt must be positive")
        token = os.environ.get("GITHUB_TOKEN", "")
        if args.command in ("check-run", "check-migration-run"):
            current = {"head_sha": git("rev-parse", "HEAD"),
                       "ref": os.environ["GITHUB_REF"],
                       "repo": os.environ["GITHUB_REPOSITORY"]}
            if current["head_sha"] != os.environ["GITHUB_SHA"]:
                raise ContinuationError("checkout is not the workflow event head")
            run = api_run(args.run_id, args.attempt, token, current["repo"])
            if args.command == "check-run":
                verify_run(run, args.run_id, args.attempt, current)
            else:
                verify_migration_run(run, args.run_id, args.attempt, current)
        elif args.command == "restore":
            restore(args.run_id, args.attempt, token)
        else:
            migrate(args.run_id, args.attempt, token)
    elif args.command == "publish":
        if not 1 <= args.boot_seconds <= 3600:
            parser.error("boot seconds must be within the bounded QEMU runtime")
        publish(args.boot_runs, args.boot_seconds)
    else:
        rollback()


if __name__ == "__main__":
    main()
