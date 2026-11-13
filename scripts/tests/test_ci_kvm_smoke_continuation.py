"""A writable KVM disk resumes only from a stopped exact-source run."""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import scripts.ci_kvm_disk_continuation as disk


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "rust-micro/.tmp").mkdir(parents=True)
        (self.root / "rust-micro/.tmp/hive.dat").write_bytes(b"generated hive")
        self.paths = {
            "DISK": self.root / "disk.img",
            "BACKUP": self.root / "baseline.img",
            "FAILED": self.root / "failed.img",
            "IN": self.root / "incoming",
            "OUT": self.root / "outgoing",
            "RECEIPT": self.root / "receipt.json",
            "ROLLBACK_MARKER": self.root / "rolled-back",
            "MIGRATION_CANDIDATE": self.root / "migration-candidate.img",
        }
        for name, path in self.paths.items():
            self.enterContext(patch.object(disk, name, path))
        self.paths["IN"].mkdir()
        self.baseline = b"baseline boot disk contents"
        self.advanced = b"advanced boot disk contents"
        self.paths["DISK"].write_bytes(self.baseline)
        self.current = {
            "head_sha": "a" * 40, "ref": "refs/heads/codex/pr314",
            "repo": "stakach/userspace-ntos", "workflow": disk.WORKFLOW,
            "submodule_sha": "b" * 40, "libernt_manifest_sha256": "c" * 64,
            "base_disk_sha256": sha(self.baseline),
            "disk_size_bytes": len(self.baseline),
            "rootserver_sha256": "d" * 64, "kernel_sha256": "e" * 64,
            "ntdll_sha256": "f" * 64, "image_profile": "production",
        }
        # The fixture uses equal byte lengths so a valid restore can pass its size gate.
        self.assertEqual(len(self.baseline), len(self.advanced))
        self.paths["IN"].joinpath("disk.img").write_bytes(self.advanced)
        self.manifest = {
            "schema": 1, "source_run_id": 101, "source_run_attempt": 2,
            "source_head_sha": self.current["head_sha"],
            "source_ref": self.current["ref"], "source_repo": self.current["repo"],
            "workflow": disk.WORKFLOW,
            **{key: self.current[key] for key in (
                "submodule_sha", "libernt_manifest_sha256", "base_disk_sha256",
                "disk_size_bytes", "rootserver_sha256", "kernel_sha256",
                "ntdll_sha256", "image_profile",
            )},
            "disk_sha256": sha(self.advanced), "qemu_stopped": True,
            "boot_runs": 2, "boot_seconds": 300,
        }
        self.paths["IN"].joinpath("manifest.json").write_text(json.dumps(self.manifest))
        self.run = {
            "id": 101, "run_attempt": 2, "status": "completed",
            "conclusion": "success", "event": "workflow_dispatch",
            "head_sha": self.current["head_sha"],
            "repository": {"full_name": self.current["repo"]},
            "head_repository": {"full_name": self.current["repo"]},
            "path": disk.WORKFLOW, "head_branch": "codex/pr314",
        }
        self.enterContext(patch.dict(os.environ, {"GITHUB_RUN_ID": "202"}))

    def restore(self):
        with patch.object(disk, "expected_build", return_value=self.current), \
             patch.object(disk, "ROOT", self.root), \
             patch.object(disk, "api_run", return_value=self.run), \
             patch.object(disk, "no_qemu_owner"):
            disk.restore(101, 2, "test-token")

    def test_exact_successful_run_restores_full_disk_and_retains_baseline(self):
        self.restore()
        self.assertEqual(self.paths["DISK"].read_bytes(), self.advanced)
        self.assertEqual(self.paths["BACKUP"].read_bytes(), self.baseline)
        receipt = json.loads(self.paths["RECEIPT"].read_text())
        self.assertEqual(receipt["source_run_attempt"], 2)

    def test_wrong_head_attempt_or_prior_conclusion_preserves_generated_disk(self):
        for field, value in (("head_sha", "0" * 40), ("run_attempt", 1),
                             ("conclusion", "failure")):
            with self.subTest(field=field):
                self.run[field] = value
                with self.assertRaises(disk.ContinuationError):
                    self.restore()
                self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)
                self.assertFalse(self.paths["BACKUP"].exists())
                self.run[field] = self.current["head_sha"] if field == "head_sha" else (
                    2 if field == "run_attempt" else "success")

    def test_mismatched_provenance_size_or_hash_preserves_generated_disk(self):
        for key, value in (("submodule_sha", "0" * 40),
                           ("libernt_manifest_sha256", "0" * 64),
                           ("base_disk_sha256", "bad"),
                           ("qemu_stopped", False),
                           ("disk_size_bytes", 12),
                           ("disk_sha256", "0" * 64)):
            with self.subTest(key=key):
                changed = {**self.manifest, key: value}
                self.paths["IN"].joinpath("manifest.json").write_text(json.dumps(changed))
                with self.assertRaises(disk.ContinuationError):
                    self.restore()
                self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)
                self.assertFalse(self.paths["BACKUP"].exists())

    def test_source_and_current_generated_baselines_can_have_different_bytes(self):
        self.manifest["base_disk_sha256"] = sha(b"source Simpleboot GUID and timestamp")
        self.paths["IN"].joinpath("manifest.json").write_text(json.dumps(self.manifest))
        self.restore()
        self.assertEqual(self.paths["DISK"].read_bytes(), self.advanced)
        self.assertEqual(self.paths["BACKUP"].read_bytes(), self.baseline)

    def test_source_run_lookup_uses_the_requested_attempt(self):
        response = io.BytesIO(b'{"id": 101}')
        with patch.object(disk.urllib.request, "urlopen", return_value=response) as lookup:
            self.assertEqual(disk.api_run(101, 2, "token", self.current["repo"]), {"id": 101})
        request = lookup.call_args.args[0]
        self.assertTrue(request.full_url.endswith("/actions/runs/101/attempts/2"))

    def test_symlink_disk_is_rejected_before_replacing_baseline(self):
        incoming = self.paths["IN"] / "disk.img"
        incoming.unlink()
        incoming.symlink_to(self.paths["DISK"])
        with self.assertRaises(disk.ContinuationError):
            self.restore()
        self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)
        self.assertFalse(self.paths["BACKUP"].exists())

    def test_symlink_input_directory_is_rejected(self):
        actual = self.root / "actual-incoming"
        self.paths["IN"].rename(actual)
        self.paths["IN"].symlink_to(actual, target_is_directory=True)
        with self.assertRaises(disk.ContinuationError):
            self.restore()
        self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)

    def test_publish_records_full_stopped_disk_and_final_hash(self):
        self.paths["DISK"].write_bytes(self.advanced)
        final_hash = self.root / "native-kvm-image-after-boot2.sha256"
        final_hash.write_text(f"{sha(self.advanced)}  disk.img\n")
        self.enterContext(patch.object(disk, "ROOT", self.root))
        with patch.object(disk, "stopped"), \
             patch.object(disk, "expected_build_after_boot", return_value=self.current.copy()), \
             patch.object(disk.subprocess, "check_output", return_value="QEMU 9.0\n"), \
             patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            disk.publish(2, 300)
        self.assertEqual((self.paths["OUT"] / "disk.img").read_bytes(), self.advanced)
        published = json.loads((self.paths["OUT"] / "manifest.json").read_text())
        self.assertEqual(published["disk_sha256"], sha(self.advanced))
        self.assertEqual(published["source_run_attempt"], 2)
        self.assertTrue(published["qemu_stopped"])

    def test_publish_carries_migration_origin_in_disk_artifact(self):
        origin = {
            "mode": "migration", "source_run_id": 101,
            "source_run_attempt": 2, "source_head_sha": "1" * 40,
            "target_head_sha": self.current["head_sha"],
            "base_disk_sha256": sha(self.baseline),
        }
        self.paths["RECEIPT"].write_text(json.dumps(origin))
        self.paths["DISK"].write_bytes(self.advanced)
        (self.root / "native-kvm-image-after-boot1.sha256").write_text(sha(self.advanced) + "\n")
        self.enterContext(patch.object(disk, "ROOT", self.root))
        with patch.object(disk, "stopped"), \
             patch.object(disk, "expected_build_after_boot", return_value=self.current.copy()), \
             patch.object(disk.subprocess, "check_output", return_value="QEMU 9.0\n"), \
             patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            disk.publish(1, 300)
        published = json.loads((self.paths["OUT"] / "manifest.json").read_text())
        self.assertEqual(published["disk_origin"], origin)

    def test_failed_resumed_boot_rolls_back_once_after_stop_receipt(self):
        self.restore()
        with patch.object(disk, "stopped"), patch.object(disk, "no_qemu_owner"):
            disk.rollback()
        self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)
        self.assertEqual(self.paths["FAILED"].read_bytes(), self.advanced)
        self.assertTrue(self.paths["ROLLBACK_MARKER"].exists())
        with patch.object(disk, "stopped"), self.assertRaises(disk.ContinuationError):
            disk.rollback()

    def test_rollback_marker_failure_does_not_overwrite_restored_baseline(self):
        self.restore()
        self.paths["ROLLBACK_MARKER"].mkdir()
        with patch.object(disk, "stopped"), patch.object(disk, "no_qemu_owner"), \
             self.assertRaises(OSError):
            disk.rollback()
        self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)
        self.assertEqual(self.paths["FAILED"].read_bytes(), self.advanced)

    def test_cross_commit_is_refused_by_exact_head_but_accepted_by_explicit_migration(self):
        prior = "1" * 40
        self.run["head_sha"] = prior
        self.manifest["source_head_sha"] = prior
        self.paths["IN"].joinpath("manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaises(disk.ContinuationError):
            self.restore()
        with patch.object(disk, "source_is_ancestor", return_value=True):
            disk.verify_migration_run(self.run, 101, 2, self.current)
            disk.verify_migration_manifest(self.manifest, 101, 2, self.current, self.run)
        self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)

    def test_migration_rejects_unrelated_head_release_or_layout(self):
        prior = "1" * 40
        self.run["head_sha"] = prior
        self.manifest["source_head_sha"] = prior
        with patch.object(disk, "source_is_ancestor", return_value=False):
            with self.assertRaises(disk.ContinuationError):
                disk.verify_migration_run(self.run, 101, 2, self.current)
        with patch.object(disk, "source_is_ancestor", return_value=True):
            disk.verify_migration_run(self.run, 101, 2, self.current)
        for key in ("libernt_manifest_sha256", "submodule_sha", "disk_size_bytes", "image_profile"):
            with self.subTest(key=key):
                changed = {**self.manifest, key: "wrong"}
                with self.assertRaises(disk.ContinuationError):
                    disk.verify_migration_manifest(changed, 101, 2, self.current, self.run)

    def test_old_source_without_hive_receipt_needs_unchanged_installed_hive(self):
        hive = self.root / "rust-micro/.tmp/hive.dat"
        hive.parent.mkdir(parents=True, exist_ok=True)
        hive.write_bytes(b"generated hive")
        self.enterContext(patch.object(disk, "ROOT", self.root))
        def read_hive(image, offset, name):
            self.assertEqual(name, "SYSTEM.DAT")
            return b"generated hive" if image == self.paths["DISK"] else b"advanced guest hive"
        with patch.object(disk, "esp_geometry", return_value=(1024, 4096)), \
             patch.object(disk, "esp_file", side_effect=read_hive), \
             self.assertRaises(disk.ContinuationError):
            disk.verify_hive_provenance(self.manifest, self.paths["IN"] / "disk.img")
        self.manifest["generated_hive_sha256"] = sha(b"generated hive")
        with patch.object(disk, "esp_geometry", return_value=(1024, 4096)), \
             patch.object(disk, "esp_file", side_effect=read_hive):
            disk.verify_hive_provenance(self.manifest, self.paths["IN"] / "disk.img")

    def test_migration_rejects_stale_unmigrated_seh_linkage(self):
        staged = self.root / "rust-micro/.tmp/simpleboot-esp"
        (staged / "Windows/system32").mkdir(parents=True)
        (staged / "simpleboot.cfg").write_bytes(b"boot config")
        (staged / "Windows/system32/nt-seh-linkage.dll").write_bytes(b"new helper")
        manifest = self.root / "rust-micro/vendor/libernt/manifest.txt"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("acpi_sha256=" + sha(b"released acpi") + "\n")
        self.enterContext(patch.object(disk, "ROOT", self.root))

        def read_file(image, offset, name):
            if name == disk.RELEASED_ACPI:
                return b"released acpi"
            if name == "simpleboot.cfg":
                return b"boot config"
            if name == "Windows/system32/nt-seh-linkage.dll":
                return b"new helper" if image == self.paths["DISK"] else b"old helper"
            raise AssertionError(name)

        with patch.object(disk, "esp_geometry", return_value=(1024, 4096)), \
             patch.object(disk, "esp_file", side_effect=read_file), \
             patch.object(disk, "driver_inventory", return_value={"acpi.sys"}), \
             self.assertRaises(disk.ContinuationError):
            disk.patch_migration_esp(self.paths["MIGRATION_CANDIDATE"],
                                     self.paths["IN"] / "disk.img", self.current)

    def test_migration_refuses_source_only_ancestor_driver(self):
        manifest = self.root / "rust-micro/vendor/libernt/manifest.txt"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("acpi_sha256=" + sha(b"released acpi") + "\n")
        self.enterContext(patch.object(disk, "ROOT", self.root))

        def inventory(image, offset):
            if image == self.paths["IN"] / "disk.img":
                return {"acpi.sys", "removed_fixture.sys"}
            return {"acpi.sys"}

        with patch.object(disk, "esp_geometry", return_value=(1024, 4096)), \
             patch.object(disk, "esp_file", return_value=b"released acpi"), \
             patch.object(disk, "driver_inventory", side_effect=inventory), \
             self.assertRaisesRegex(disk.ContinuationError, "driver inventory"):
            disk.patch_migration_esp(self.paths["MIGRATION_CANDIDATE"],
                                     self.paths["IN"] / "disk.img", self.current)

    def test_migration_transaction_preserves_source_and_generated_baseline(self):
        prior = "1" * 40
        self.run["head_sha"] = prior
        self.manifest["source_head_sha"] = prior
        self.paths["IN"].joinpath("manifest.json").write_text(json.dumps(self.manifest))

        def patch_candidate(candidate, source, current):
            self.assertEqual(candidate.read_bytes(), self.advanced)
            self.assertEqual(source.read_bytes(), self.advanced)
            candidate.write_bytes(b"M" + self.advanced[1:])
            return {"kernel": {"source_sha256": "a" * 64, "target_sha256": "b" * 64}}

        with patch.object(disk, "expected_build", return_value=self.current), \
             patch.object(disk, "ROOT", self.root), \
             patch.object(disk, "api_run", return_value=self.run), \
             patch.object(disk, "source_is_ancestor", return_value=True), \
             patch.object(disk, "verify_hive_provenance"), \
             patch.object(disk, "no_qemu_owner"), \
             patch.object(disk, "patch_migration_esp", side_effect=patch_candidate):
            disk.migrate(101, 2, "test-token")
        self.assertEqual(self.paths["IN"].joinpath("disk.img").read_bytes(), self.advanced)
        self.assertEqual(self.paths["DISK"].read_bytes(), b"M" + self.advanced[1:])
        self.assertEqual(self.paths["BACKUP"].read_bytes(), self.baseline)
        receipt = json.loads(self.paths["RECEIPT"].read_text())
        self.assertEqual(receipt["mode"], "migration")
        self.assertEqual(receipt["source_head_sha"], prior)
        self.assertEqual(receipt["target_head_sha"], self.current["head_sha"])

    def test_migration_patch_failure_does_not_replace_generated_disk(self):
        prior = "1" * 40
        self.run["head_sha"] = prior
        self.manifest["source_head_sha"] = prior
        self.paths["IN"].joinpath("manifest.json").write_text(json.dumps(self.manifest))
        with patch.object(disk, "expected_build", return_value=self.current), \
             patch.object(disk, "ROOT", self.root), \
             patch.object(disk, "api_run", return_value=self.run), \
             patch.object(disk, "source_is_ancestor", return_value=True), \
             patch.object(disk, "verify_hive_provenance"), \
             patch.object(disk, "no_qemu_owner"), \
             patch.object(disk, "patch_migration_esp", side_effect=disk.ContinuationError("write failed")), \
             self.assertRaises(disk.ContinuationError):
            disk.migrate(101, 2, "test-token")
        self.assertEqual(self.paths["DISK"].read_bytes(), self.baseline)
        self.assertFalse(self.paths["BACKUP"].exists())
        self.assertFalse(self.paths["RECEIPT"].exists())
        self.assertEqual(self.paths["IN"].joinpath("disk.img").read_bytes(), self.advanced)

    @unittest.skipUnless(shutil.which("mcopy") and shutil.which("mmd") and
                         shutil.which("mdir") and shutil.which("mkfs.fat"),
                         "FAT image tools are unavailable")
    def test_fat_replacement_reads_back_only_the_selected_file(self):
        image = self.root / "fat.img"
        with image.open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        subprocess.run(["mkfs.fat", "-F", "32", str(image)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        old = self.root / "old"
        new = self.root / "new"
        acpi = self.root / "acpi"
        old.write_bytes(b"old kernel")
        new.write_bytes(b"new kernel")
        acpi.write_bytes(b"released acpi")
        subprocess.run(["mcopy", "-i", str(image), str(old), "::/kernel"], check=True)
        subprocess.run(["mcopy", "-i", str(image), str(acpi), "::/acpi.sys"], check=True)
        for name in ("Windows", "Windows/system32", "Windows/system32/drivers"):
            subprocess.run(["mmd", "-i", str(image), f"::/{name}"], check=True)
        subprocess.run(["mcopy", "-i", str(image), str(acpi),
                        "::/Windows/system32/drivers/acpi.sys"], check=True)
        self.assertEqual(disk.esp_file(image, 0, "kernel"), b"old kernel")
        disk.replace_esp_file(image, 0, "kernel", new)
        self.assertEqual(disk.esp_file(image, 0, "kernel"), b"new kernel")
        self.assertEqual(disk.esp_file(image, 0, "acpi.sys"), b"released acpi")
        self.assertEqual(disk.driver_inventory(image, 0), {"acpi.sys"})


if __name__ == "__main__":
    unittest.main()
