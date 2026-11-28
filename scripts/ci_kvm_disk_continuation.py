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
POST_SETUP_IDLE_MARKER = ROOT / "native-kvm-post-setup-idle.txt"
BOUND_REACHED_MARKER = ROOT / "native-kvm-bound-reached.txt"
# How the source boot ended, and the only run conclusion each kind of disk may come from.
# A desktop disk comes from boots that passed the desktop gate. A failed run publishes only
# a disk the runner marked: post-setup-idle (stationary after setup completed and a user
# logged on) or bound-reached (the whole bound ran without a fault before any desktop).
# Every other failed boot is rolled back, never published. `bounded` is the pre-gate kind,
# when a run that reached its bound concluded success.
STOP_CONCLUSIONS = {"desktop": "success", "post-setup-idle": "failure",
                    "bound-reached": "failure", "bounded": "success"}


def stop_marker(stop):
    """The runner's evidence marker a failed run's stop kind must be published with."""
    return {"post-setup-idle": POST_SETUP_IDLE_MARKER,
            "bound-reached": BOUND_REACHED_MARKER}.get(stop)
MIGRATION_CANDIDATE = DISK.with_name("disk.migration-candidate.img")
WORKFLOW = ".github/workflows/native-kvm-smoke.yml"
MAX_DISK_BYTES = 2 * 1024**3
MIB = 1024 * 1024
OLD_PERSIST_BYTES = 32 * MIB
NEW_PERSIST_BYTES = 96 * MIB
OLD_SNAPSHOT_SLOT_BYTES = 8 * MIB
NEW_SNAPSHOT_SLOT_BYTES = 32 * MIB
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


def verify_conclusion(run: dict) -> None:
    if run.get("conclusion") not in STOP_CONCLUSIONS.values():
        raise ContinuationError("source run conclusion mismatch")


def verify_stop(run: dict, manifest: dict) -> None:
    """A disk is usable only from the run conclusion its recorded stop kind allows."""
    stop = manifest.get("stop", "bounded")
    if STOP_CONCLUSIONS.get(stop) != run.get("conclusion"):
        raise ContinuationError("source disk stop kind does not match its run conclusion")


def verify_run(run: dict, run_id: int, attempt: int, current: dict) -> None:
    expected = {
        "id": run_id, "run_attempt": attempt, "status": "completed",
        "event": "workflow_dispatch",
        "head_sha": current["head_sha"],
    }
    for key, value in expected.items():
        if run.get(key) != value:
            raise ContinuationError(f"source run {key} mismatch")
    verify_conclusion(run)
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


def source_is_ancestor(source_head: str, target_head: str, cwd: Path = ROOT) -> bool:
    if not COMMIT.fullmatch(source_head) or not COMMIT.fullmatch(target_head):
        return False
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_head, target_head],
        cwd=cwd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def api_commit_tree(commit_sha: str, token: str, repo: str) -> str | None:
    """Read one exact commit tree from the authenticated source repository."""
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) \
            or not COMMIT.fullmatch(commit_sha):
        return None
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/commits/{commit_sha}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(value, dict) or value.get("sha") != commit_sha:
        return None
    commit = value.get("commit")
    tree = commit.get("tree") if isinstance(commit, dict) else None
    tree_sha = tree.get("sha") if isinstance(tree, dict) else None
    return tree_sha if isinstance(tree_sha, str) and COMMIT.fullmatch(tree_sha) else None


def source_matches_target_ancestor_tree(
    source_head: str, target_head: str, repo: str | None = None, token: str | None = None,
) -> bool:
    """Accept a pre-squash source only when its complete tree is in target history.

    A squash merge can replace a commit without changing its source tree. The installed
    disk is still authenticated by its run, manifest and hash; this check only establishes
    that the source build corresponds to an actual ancestor of the target build.
    """
    if not isinstance(source_head, str) or not isinstance(target_head, str) \
            or not COMMIT.fullmatch(source_head) or not COMMIT.fullmatch(target_head):
        return False
    try:
        def verified_commit(sha: str) -> bool:
            try:
                resolved = subprocess.check_output(
                    ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
                    cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
                ).strip()
                return resolved == sha
            except (OSError, subprocess.CalledProcessError):
                return False

        if not verified_commit(target_head):
            return False
        if verified_commit(source_head):
            source_tree = subprocess.check_output(
                ["git", "rev-parse", "--verify", f"{source_head}^{{tree}}"],
                cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
            ).strip()
        else:
            # Squash merges can leave the source run's commit absent from a fresh checkout.
            # The Actions run authenticates its exact SHA and repository before this lookup.
            source_tree = api_commit_tree(source_head, token or "", repo or "")
        if not isinstance(source_tree, str) or not COMMIT.fullmatch(source_tree):
            return False
        ancestor_trees = subprocess.check_output(
            ["git", "log", "--format=%T", target_head],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return source_tree in ancestor_trees.splitlines()


def migration_submodule_is_compatible(source_sha: object, current_sha: str) -> bool:
    """The kernel submodule may advance or keep the same tree after a squash merge.

    Migration replaces the kernel and boot payload on the ESP with this build's, and the
    disk length and ESP geometry are checked separately, so a source built from an earlier
    ancestor of the current kernel commit is migratable like an earlier parent commit is.
    A squash merge can replace the commit without changing its complete tree.
    """
    if not isinstance(source_sha, str) or not COMMIT.fullmatch(source_sha) \
            or not COMMIT.fullmatch(current_sha):
        return False
    kernel = ROOT / "rust-micro"
    if source_sha == current_sha or source_is_ancestor(source_sha, current_sha, cwd=kernel):
        return True

    def commit_tree(sha: str) -> str | None:
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=kernel,
                text=True, stderr=subprocess.DEVNULL).strip()
            if commit != sha:
                return None
            tree = subprocess.check_output(
                ["git", "rev-parse", "--verify", f"{sha}^{{tree}}"], cwd=kernel,
                text=True, stderr=subprocess.DEVNULL).strip()
            return tree if COMMIT.fullmatch(tree) else None
        except (OSError, subprocess.CalledProcessError):
            return None

    source_tree = commit_tree(source_sha)
    return source_tree is not None and source_tree == commit_tree(current_sha)


def migration_source_ref(run: dict) -> str:
    branch = run.get("head_branch")
    if not isinstance(branch, str) or not branch:
        raise ContinuationError("migration source run branch is absent")
    return f"refs/heads/{branch}"


def verify_migration_run(run: dict, run_id: int, attempt: int, current: dict) -> None:
    expected = {
        "id": run_id, "run_attempt": attempt, "status": "completed",
        "event": "workflow_dispatch",
    }
    for key, value in expected.items():
        if run.get(key) != value:
            raise ContinuationError(f"source run {key} mismatch")
    verify_conclusion(run)
    if (run.get("repository") or {}).get("full_name") != current["repo"] \
            or (run.get("head_repository") or {}).get("full_name") != current["repo"]:
        raise ContinuationError("source run belongs to another repository")
    if run.get("path", "").split("@", 1)[0] != WORKFLOW:
        raise ContinuationError("source run used another workflow")
    migration_source_ref(run)
    if run_id == int(os.environ["GITHUB_RUN_ID"]):
        raise ContinuationError("cannot migrate this same workflow run")
    source_head = run.get("head_sha")
    if not isinstance(source_head, str) or source_head == current["head_sha"] \
            or not (source_is_ancestor(source_head, current["head_sha"])
                    or source_matches_target_ancestor_tree(
                        source_head, current["head_sha"], current["repo"],
                        os.environ.get("GITHUB_TOKEN"))):
        raise ContinuationError("migration source is not an earlier ancestor tree of this head")


def verify_migration_manifest(value: dict, run_id: int, attempt: int,
                              current: dict, run: dict) -> None:
    # Other profiles can stage native fixtures and a different initial hive. Their
    # code/data migration set needs its own explicit contract.
    if current["image_profile"] != "production":
        raise ContinuationError("cross-commit migration is limited to production images")
    expected = {
        "source_run_id": run_id, "source_run_attempt": attempt,
        "source_head_sha": run["head_sha"], "source_ref": migration_source_ref(run),
        "source_repo": current["repo"], "workflow": WORKFLOW,
    }
    expected.update({key: current[key] for key in (
        "libernt_manifest_sha256", "image_profile",
    )})
    for key, target in expected.items():
        if value.get(key) != target:
            raise ContinuationError(f"migration {key} differs from source or current build")
    if not migration_size_shape(value.get("disk_size_bytes"), current["disk_size_bytes"]):
        raise ContinuationError("migration disk_size_bytes differs from source or current build")
    if not migration_submodule_is_compatible(value.get("submodule_sha"), current["submodule_sha"]):
        raise ContinuationError("migration submodule_sha is not this build's ancestor or exact tree")
    for key in ("disk_sha256", "base_disk_sha256", "kernel_sha256",
                "rootserver_sha256", "ntdll_sha256"):
        if not isinstance(value.get(key), str) or not SHA256.fullmatch(value[key]):
            raise ContinuationError(f"migration {key} is invalid")
    if value.get("qemu_stopped") is not True:
        raise ContinuationError("source QEMU stop receipt absent")


def migration_size_shape(source_bytes: object, target_bytes: object) -> bool:
    """Only an unchanged disk or the one supported 32-to-96 MiB tail growth."""
    return type(source_bytes) is int and type(target_bytes) is int \
        and source_bytes > 0 and target_bytes <= MAX_DISK_BYTES \
        and (source_bytes == target_bytes
             or target_bytes - source_bytes == NEW_PERSIST_BYTES - OLD_PERSIST_BYTES)


def gpt_base_bytes(image: Path) -> int:
    """The GPT alternate LBA locates the end of Simpleboot's FAT-visible disk."""
    with image.open("rb") as disk_file:
        disk_file.seek(512)
        header = disk_file.read(92)
    if header[:8] != b"EFI PART" or int.from_bytes(header[24:32], "little") != 1:
        raise ContinuationError("migration has no expected primary GPT header")
    alternate = int.from_bytes(header[32:40], "little")
    if alternate < 34 or alternate >= MAX_DISK_BYTES // 512:
        raise ContinuationError("migration has invalid GPT disk geometry")
    return (alternate + 1) * 512


def migration_expansion_base(source: Path, target: Path,
                             source_bytes: int, target_bytes: int) -> int | None:
    """Prove both images share one base before moving any persistent bytes."""
    if source_bytes == target_bytes:
        return None
    if not migration_size_shape(source_bytes, target_bytes):
        raise ContinuationError("migration disk tail has unsupported sizes")
    base = gpt_base_bytes(source)
    if base != gpt_base_bytes(target) or source_bytes != base + OLD_PERSIST_BYTES \
            or target_bytes != base + NEW_PERSIST_BYTES:
        raise ContinuationError("migration disk tail differs from verified 32-to-96 MiB geometry")
    return base


def copy_region(source: Path, target: Path, source_start: int,
                target_start: int, length: int) -> None:
    with source.open("rb") as incoming, target.open("r+b") as candidate:
        incoming.seek(source_start)
        candidate.seek(target_start)
        while length:
            block = incoming.read(min(length, MIB))
            if not block:
                raise ContinuationError("snapshot slot ended early during migration")
            candidate.write(block)
            length -= len(block)


def extend_snapshot_tail(candidate: Path, source: Path, base: int,
                         target_bytes: int) -> None:
    with candidate.open("r+b") as image:
        image.truncate(target_bytes)
    for slot in range(2):
        copy_region(source, candidate, base + slot * OLD_SNAPSHOT_SLOT_BYTES,
                    base + OLD_PERSIST_BYTES + slot * NEW_SNAPSHOT_SLOT_BYTES,
                    OLD_SNAPSHOT_SLOT_BYTES)


def verify_expanded_snapshot_tail(candidate: Path, source: Path, base: int) -> None:
    zero = hashlib.sha256()
    zero_block = bytes(MIB)
    for _ in range((NEW_SNAPSHOT_SLOT_BYTES - OLD_SNAPSHOT_SLOT_BYTES) // MIB):
        zero.update(zero_block)
    zero_hash = zero.hexdigest()
    for slot in range(2):
        old = base + slot * OLD_SNAPSHOT_SLOT_BYTES
        new = base + OLD_PERSIST_BYTES + slot * NEW_SNAPSHOT_SLOT_BYTES
        if region_digest(candidate, new, OLD_SNAPSHOT_SLOT_BYTES) != \
                region_digest(source, old, OLD_SNAPSHOT_SLOT_BYTES):
            raise ContinuationError("migration snapshot slot copy differs from source")
        if region_digest(candidate, new + OLD_SNAPSHOT_SLOT_BYTES,
                         NEW_SNAPSHOT_SLOT_BYTES - OLD_SNAPSHOT_SLOT_BYTES) != zero_hash:
            raise ContinuationError("migration new snapshot slot slack is not zero")


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
    source_bytes = require_regular(source, MAX_DISK_BYTES)
    for start, count in ((0, offset), (end, source_bytes - end)):
        if region_digest(source, start, count) != region_digest(candidate, start, count):
            raise ContinuationError("migration changed bytes outside the ESP")
    return changes


def publish(boot_runs: int, boot_seconds: int, stop: str = "desktop") -> None:
    stopped()
    evidence = None
    if stop == "bounded":
        raise ContinuationError("bounded is a pre-gate stop kind; publish desktop or a marked stop")
    if marker := stop_marker(stop):
        try:
            require_regular(marker, 4096)
        except (OSError, ContinuationError) as error:
            raise ContinuationError(f"{stop} evidence marker absent") from error
        evidence = marker.read_text().strip()
        if not evidence:
            raise ContinuationError(f"{stop} evidence marker is empty")
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
            "boot_runs": boot_runs, "boot_seconds": boot_seconds, "stop": stop,
            "qemu_version": subprocess.check_output(
                ["qemu-system-x86_64", "--version"], text=True).splitlines()[0],
        }
        if evidence:
            manifest[f"{stop.replace('-', '_')}_evidence"] = evidence
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
    run = api_run(run_id, attempt, token, current["repo"])
    verify_run(run, run_id, attempt, current)
    if not stat.S_ISDIR(IN.lstat().st_mode):
        raise ContinuationError("continuation input is not a real directory")
    manifest = read_manifest(IN / "manifest.json")
    verify_stop(run, manifest)
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
    verify_stop(run, manifest)
    verify_migration_manifest(manifest, run_id, attempt, current, run)
    incoming = IN / "disk.img"
    source_bytes = require_regular(incoming, MAX_DISK_BYTES)
    if source_bytes != manifest["disk_size_bytes"]:
        raise ContinuationError("source disk length differs from migration manifest")
    if digest(incoming) != manifest["disk_sha256"]:
        raise ContinuationError("source disk SHA-256 mismatch")
    base = migration_expansion_base(incoming, DISK, source_bytes, current["disk_size_bytes"])
    verify_hive_provenance(manifest, incoming)
    no_qemu_owner()
    if any(path.exists() for path in (BACKUP, RECEIPT, FAILED, MIGRATION_CANDIDATE)):
        raise ContinuationError("another continuation, migration, or rollback is present")
    candidate = MIGRATION_CANDIDATE
    try:
        shutil.copyfile(incoming, candidate)
        if base is not None:
            extend_snapshot_tail(candidate, incoming, base, current["disk_size_bytes"])
        changes = patch_migration_esp(candidate, incoming, current)
        if require_regular(candidate, MAX_DISK_BYTES) != current["disk_size_bytes"]:
            raise ContinuationError("migration changed disk length")
        if base is not None:
            verify_expanded_snapshot_tail(candidate, incoming, base)
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
            "source_submodule_sha": manifest["submodule_sha"],
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
    publish_command.add_argument("--stop", choices=sorted(set(STOP_CONCLUSIONS) - {"bounded"}),
                                 default="desktop")
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
        publish(args.boot_runs, args.boot_seconds, args.stop)
    else:
        rollback()


if __name__ == "__main__":
    main()
