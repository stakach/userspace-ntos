//! `writable_fs` — the executive's WRITABLE filesystem overlay.
//!
//! ## What this is
//!
//! The `\reactos` volume the hosted processes boot off is a **read-only** FAT32 reader
//! (`fs_loader`): it can resolve any path to bytes, and nothing more. Everything a real NT session
//! does the moment a user logs on — `CreateDirectoryW("C:\Profiles")`, writing a profile, creating
//! `ntuser.dat` — needs a filesystem that can be WRITTEN. Without one, `NtCreateFile` on those
//! paths failed as invalid-function to user mode and `CreateUserProfileW` stopped at
//! `userenv/profile.c:929`.
//!
//! This module mounts a **real** filesystem over the writable part of the namespace. Real means
//! real: create/open with every disposition, `FILE_DIRECTORY_FILE`, read, write at an offset or at
//! the file-object's own position, query/set information, directory ENUMERATION (`.`, `..`, the
//! children), delete-on-close, and the correct NTSTATUS for each miss. Nothing here fabricates a
//! success — a `CreateDirectory` that this volume cannot satisfy still fails.
//!
//! ## The seam
//!
//! * **Namespace.** Some subtrees are prefix-owned by the writable volume: their canonical
//!   volume-relative form (the same [`nt_fs::nt_path_to_volume_relative`] canonicalisation the
//!   read-only reader uses) is at or under one of [`WRITABLE_PREFIXES`]. Other fixed-drive paths can
//!   still acquire real writable-layer entries when user mode creates them, while installed files
//!   remain sourced from the read-only FAT image until they are actually written.
//! * **Backing.** [`nt_fs::MemFs`] behind the [`nt_fs::FileSystem`] `Zw*` facade, restored from and
//!   checkpointed to the raw snapshot reserve after the FAT volume when that reserve contains a valid
//!   snapshot. The callers stay above the `Zw*` seam: persistence changes the backing source, not
//!   create/read/write semantics.
//! * **Handles.** An open file object is owned by a per-process `nt-process` handle
//!   (`HandleObject::OverlayFile`), so it is closable, duplicable and reclaimed with the process
//!   like every other executive object.

use crate::*;
use nt_fs::SnapshotBlockDevice;

#[path = "writable_fs/snapshot_storage.rs"]
pub(crate) mod snapshot_storage;

#[path = "writable_fs/native_snapshot_io.rs"]
pub(crate) mod native_snapshot_io;

#[path = "writable_fs/native_checkpoint.rs"]
mod native_checkpoint;

#[path = "writable_fs/snapshot_capture.rs"]
mod snapshot_capture;

#[path = "writable_fs/registry_journal.rs"]
pub(crate) mod registry_journal;

#[path = "writable_fs/registry_wal.rs"]
pub(crate) mod registry_wal;

#[path = "writable_fs/hive_wal.rs"]
pub(crate) mod hive_wal;

#[path = "writable_fs/system_wal_fold.rs"]
mod system_wal_fold;
pub(crate) use system_wal_fold::{fold_system_wal_if_dirty,
    redrive_retained_system_wal_fold_after_native_completion, system_wal_fold_ack_pending};

#[path = "writable_fs/file_cleanup.rs"]
mod file_cleanup;
pub(crate) use file_cleanup::{
    acquire_file_io, adopt_file_io, cancel_file_io_waiter, cancel_promoted_file_io,
    file_io_mode, file_io_waiter_count, promote_file_io_waiter, release_file_io, set_file_mode,
    redrive_file_cleanup_work,
};
use file_cleanup::publish_file_cleanup_effects;

/// The namespace subtrees served by the writable volume, as canonical volume-relative paths
/// (lowercase, `\`-separated, no leading separator — the form `nt_path_to_volume_relative` emits).
///
/// `users` is `%SystemDrive%\Users`, the `ProfilesDirectory` the installed SOFTWARE hive names and
/// the tree winlogon's `LoadUserProfileW` -> `CreateUserProfileW` builds.
///
/// `windows\system32\config` is the installed-system state directory. Ordinary services can create
/// their own state files there through `NtCreateFile` rather than hitting the read-only FAT reader.
/// Boot hive source files stay on the FAT volume until the Configuration Manager flushes a live
/// mutable hive checkpoint into the writable layer. EventLog's `AppEvent.Evt`/`SecEvent.Evt`/
/// `SysEvent.Evt` files are the first real users.
///
/// `windows\bootstat.dat` is an exact installed mutable file. The RTL opens, reads, writes and
/// flushes it through ordinary file syscalls; it has no executive-private backing object.
pub(crate) const WRITABLE_PREFIXES: &[&[u8]] = &[
    crate::installed_layout::USERS,
    crate::installed_layout::CONFIG,
    crate::installed_layout::BOOTSTAT,
];

const BOOT_STATUS_PATH: &str = crate::installed_layout::NT_BOOTSTAT;
const BOOT_STATUS_VOLUME_RELATIVE: &[u8] = crate::installed_layout::BOOTSTAT;
const BOOT_STATUS_DATA_SIZE: usize = 0x88;

fn initial_boot_status_data() -> [u8; BOOT_STATUS_DATA_SIZE] {
    let mut data = [0u8; BOOT_STATUS_DATA_SIZE];
    data[0..4].copy_from_slice(&(BOOT_STATUS_DATA_SIZE as u32).to_le_bytes());
    data[4..8].copy_from_slice(&1u32.to_le_bytes()); // NtProductWinNt
    data[8] = 1; // AabEnabled
    data[9] = 30; // AabTimeout
    data[10] = 1; // LastBootSucceeded
    data
}

/// ★ BYPASS SWITCH (the batch's control experiment). `false` unmounts the writable volume: every
/// path below fails as `STATUS_DEVICE_NOT_READY`, `CreateDirectoryW` fails again, and the overlay
/// specs go red. Nothing else in the executive changes.
pub(crate) const WRITABLE_OVERLAY_MOUNTED: bool = true;

/// Materialise the installed `Users` tree into the writable volume before profile creation.
/// `CreateUserProfileExW` copies `C:\Users\Default` through ordinary file APIs, so the source
/// directories and the destination must share the writable namespace.
pub(crate) const PROVISION_DEFAULT_USER_PROFILE: bool = true;

/// Provide the default profile's `ntuser.dat` from the live setup-provisioned `.Default`
/// hive. Winlogon's own `CopyDirectory` copies it to the newly created user profile.
pub(crate) const PROVISION_NTUSER_DAT: bool = true;

/// The `ntuser.dat` source profile and destination the copy must produce.
pub(crate) const DEFAULT_USER_NTUSER_DAT: &str = crate::installed_layout::NT_DEFAULT_NTUSER;
pub(crate) const COPIED_PROFILE_NTUSER_DAT: &str = crate::installed_layout::NT_ADMIN_NTUSER;

/// Bytes of the `ntuser.dat` really provisioned into the `Default` profile (0 = not present).
pub(crate) static NTUSER_DAT_PROVISIONED: AtomicU64 = AtomicU64::new(0);

/// The setup-provisioned `.Default` hive image to install into `Default\ntuser.dat`.
///
/// This is populated by the registry setup path after the mutable `.Default` hive has received
/// ReactOS setup's locale and shell-folder writes. If it is absent, no profile hive is provisioned:
/// copying the raw `config\default` prototype would reintroduce the stale setup-state bug.
static mut SETUP_DEFAULT_USER_NTUSER_IMAGE: Option<alloc::vec::Vec<u8>> = None;

const REGF_HIVE_MAGIC: [u8; 4] = *b"regf";

fn is_regf_hive_image(bytes: &[u8]) -> bool {
    bytes.starts_with(&REGF_HIVE_MAGIC)
}

fn is_core_hive_image(bytes: &[u8]) -> bool {
    bytes.starts_with(&nt_hive_core::HIVE_IMAGE_MAGIC)
}

/// Is `path` a REAL regf hive on this volume? Checked by CONTENT, not by existence: the bytes must
/// parse through the same `nt-hive-regf` navigator the registry mounts a hive with, AND its root
/// must really enumerate subkeys (a zero-filled or truncated file cannot fake that). Returns the
/// hive's byte length, or 0.
pub(crate) fn regf_len_on(fs: &nt_fs::FileSystem, path: &str) -> usize {
    let Some(bytes) = fs.file_bytes(path) else {
        return 0;
    };
    if !is_regf_hive_image(bytes) {
        return 0;
    }
    match RegfHive::new(bytes) {
        Some(hive) if !hive.subkeys(hive.root()).is_empty() => bytes.len(),
        _ => 0,
    }
}

fn hive_image_ok(bytes: &[u8]) -> bool {
    if is_core_hive_image(bytes) {
        return nt_hive_core::image_root_subkey_count_if_valid(bytes)
            .is_ok_and(|subkeys| subkeys > 0);
    }
    if is_regf_hive_image(bytes) {
        return RegfHive::new(bytes).is_some_and(|hive| !hive.subkeys(hive.root()).is_empty());
    }
    false
}

/// Is `path` a mountable hive image on this volume? Accepts both real on-disk `regf` hives and this
/// kernel's versioned mutable-hive checkpoints, matching `NtLoadKey`'s accepted source formats.
pub(crate) fn hive_image_len_on(fs: &nt_fs::FileSystem, path: &str) -> usize {
    let Some(bytes) = fs.file_bytes(path) else {
        return 0;
    };
    if is_core_hive_image(bytes) {
        return nt_hive_core::image_len_if_valid(bytes).unwrap_or(0);
    }
    if is_regf_hive_image(bytes) {
        return regf_len_on(fs, path);
    }
    0
}

/// Return the byte length of a value inside a hive image file on the writable volume.
///
/// This is a content proof for profile setup gates: the value must exist in the file winlogon copied
/// and `NtLoadKey` mounted, not in an executive-side fallback table.
pub(crate) fn hive_image_value_len_on(
    fs: &nt_fs::FileSystem,
    path: &str,
    key_path: &str,
    value_name: &str,
) -> usize {
    let Some(bytes) = fs.file_bytes(path) else {
        return 0;
    };
    if is_core_hive_image(bytes) {
        return nt_hive_core::image_value_len_if_valid(bytes, key_path, value_name).unwrap_or(0);
    }
    if let Some(regf) = is_regf_hive_image(bytes)
        .then(|| RegfHive::new(bytes))
        .flatten()
    {
        return regf
            .open_key(key_path)
            .and_then(|key| regf.value(key, value_name))
            .map_or(0, |(_, data)| data.len());
    }
    0
}

/// [`hive_image_len_on`] against the LIVE mounted volume (the gate specs' read-back).
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the read.
pub(crate) unsafe fn hive_image_len_at(path: &str) -> usize {
    match writable_fs() {
        Ok(fs) => hive_image_len_on(fs, path),
        Err(_) => 0,
    }
}

/// [`hive_image_value_len_on`] against the LIVE mounted volume.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the read.
pub(crate) unsafe fn hive_image_value_len_at(
    path: &str,
    key_path: &str,
    value_name: &str,
) -> usize {
    match writable_fs() {
        Ok(fs) => hive_image_value_len_on(fs, path, key_path, value_name),
        Err(_) => 0,
    }
}

/// Publish the setup-provisioned `.Default` hive image that the profile source should expose as
/// `Default User\ntuser.dat`.
///
/// # Safety
/// Single-threaded executive during boot/profile setup. The stored image is immutable after
/// publication except for replacing the whole vector with a newer setup snapshot.
pub(crate) unsafe fn set_default_user_ntuser_dat_image(image: alloc::vec::Vec<u8>) -> bool {
    if !PROVISION_NTUSER_DAT || image.is_empty() || !hive_image_ok(&image) {
        return false;
    }
    if registry_journal::owns_volume() {
        *core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE) = Some(image);
        return false;
    }
    let len = image.len() as u64;
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_some() {
        let mut image_slot = Some(image);
        let (already_current, provisioned) = {
            let fs = (*core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
                .as_mut()
                .unwrap();
            let current_image = image_slot.as_ref().map(|image| image.as_slice());
            let already_current = fs.file_bytes(DEFAULT_USER_NTUSER_DAT) == current_image;
            let provisioned = if already_current {
                true
            } else {
                match fs.provision_file_owned(DEFAULT_USER_NTUSER_DAT, image_slot.take().unwrap()) {
                    Ok(()) => true,
                    Err(returned) => {
                        image_slot = Some(returned);
                        false
                    }
                }
            };
            if provisioned {
                refresh_live_profile_source_proofs(fs);
            }
            (already_current, provisioned)
        };
        if provisioned && !already_current {
            mark_snapshot_dirty();
        }
        if provisioned {
            *core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE) = None;
            NTUSER_DAT_PROVISIONED.store(len, Ordering::Relaxed);
        } else {
            *core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE) = image_slot;
        }
        provisioned
    } else {
        *core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE) = Some(image);
        NTUSER_DAT_PROVISIONED.store(len, Ordering::Relaxed);
        true
    }
}

/// The staged tree's FAT root name, and its mount point on the writable volume.
pub(crate) const STAGED_PROFILES_DIR: &[u8] = crate::installed_layout::USERS_SOURCE;
pub(crate) const PROFILES_VOLUME_ROOT_RELATIVE: &[u8] = crate::installed_layout::USERS;
pub(crate) const STAGED_CONFIG_DIR: &[u8] = crate::installed_layout::CONFIG;
pub(crate) const CONFIG_VOLUME_ROOT_RELATIVE: &[u8] = crate::installed_layout::CONFIG;
pub(crate) const CONFIG_SYSTEM_HIVE_RELATIVE: &[u8] = crate::installed_layout::CONFIG_SYSTEM;
pub(crate) const CONFIG_SOFTWARE_HIVE_RELATIVE: &[u8] = crate::installed_layout::CONFIG_SOFTWARE;
pub(crate) const CONFIG_SECURITY_HIVE_RELATIVE: &[u8] = crate::installed_layout::CONFIG_SECURITY;
pub(crate) const CONFIG_SAM_HIVE_RELATIVE: &[u8] = crate::installed_layout::CONFIG_SAM;
pub(crate) const CONFIG_DEFAULT_HIVE_RELATIVE: &[u8] = crate::installed_layout::CONFIG_DEFAULT;
pub(crate) const CONFIG_SYSTEM_HIVE_PATH: &str = crate::installed_layout::NT_CONFIG_SYSTEM;
pub(crate) const CONFIG_SOFTWARE_HIVE_PATH: &str = crate::installed_layout::NT_CONFIG_SOFTWARE;
pub(crate) const CONFIG_SECURITY_HIVE_PATH: &str = crate::installed_layout::NT_CONFIG_SECURITY;
pub(crate) const CONFIG_SAM_HIVE_PATH: &str = crate::installed_layout::NT_CONFIG_SAM;
pub(crate) const CONFIG_DEFAULT_HIVE_PATH: &str = crate::installed_layout::NT_CONFIG_DEFAULT;
/// The installed profile-source directory that `CreateUserProfileExW` copies.
pub(crate) const PROFILE_ROOT_DIR: &str = crate::installed_layout::NT_USERS;
pub(crate) const DEFAULT_USER_PROFILE_DIR: &str = crate::installed_layout::NT_DEFAULT_PROFILE;
pub(crate) const DEFAULT_USER_PROBE_FILE: &str =
    crate::installed_layout::NT_DEFAULT_PROFILE_APPDATA;

/// The destination AppData directory that `CopyDirectory` must have produced.
pub(crate) const COPIED_PROFILE_DIR: &str = crate::installed_layout::NT_ADMIN_PROFILE;
pub(crate) const COPIED_PROFILE_PROBE_FILE: &str =
    crate::installed_layout::NT_ADMIN_PROFILE_APPDATA;

/// Whether an existing directory is present on the live writable volume, read by path.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the query.
pub(crate) unsafe fn directory_exists_at(path: &str) -> bool {
    match writable_fs() {
        Ok(fs) => fs
            .query_attributes(path)
            .is_some_and(|info| info.is_directory),
        Err(_) => false,
    }
}

/// Whether `CopyDirectory` recreated the installed profile's AppData directory.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the read.
pub(crate) unsafe fn copied_profile_probe_ok() -> bool {
    match writable_fs() {
        Ok(fs) => fs
            .query_attributes(COPIED_PROFILE_PROBE_FILE)
            .is_some_and(|info| info.is_directory),
        Err(_) => false,
    }
}

/// Directories / files / content bytes materialised from the staged `\Users` tree.
pub(crate) static PROFILE_SOURCE_DIRS: AtomicU64 = AtomicU64::new(0);
pub(crate) static PROFILE_SOURCE_FILES: AtomicU64 = AtomicU64::new(0);
pub(crate) static PROFILE_SOURCE_BYTES: AtomicU64 = AtomicU64::new(0);
/// The installed Default AppData directory, read back off the writable volume.
pub(crate) static PROFILE_SOURCE_PROBE_OK: AtomicU64 = AtomicU64::new(0);
/// Directory entries `Default` really enumerates, read back
/// through the SAME `Zw*` record encoder `NtQueryDirectoryFile` — and so `FindFirstFileW` — uses.
pub(crate) static PROFILE_SOURCE_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Directories / files / content bytes really materialised from the staged
/// `\windows\system32\config` tree.
pub(crate) static CONFIG_SOURCE_DIRS: AtomicU64 = AtomicU64::new(0);
pub(crate) static CONFIG_SOURCE_FILES: AtomicU64 = AtomicU64::new(0);
pub(crate) static CONFIG_SOURCE_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static CONFIG_SOURCE_SYSTEM_HIVE_OK: AtomicU64 = AtomicU64::new(0);
pub(crate) static CONFIG_SOURCE_SOFTWARE_HIVE_OK: AtomicU64 = AtomicU64::new(0);

/// The mounted writable volume. `None` until the first path resolves into it (the volume is
/// created lazily so a boot that never writes pays nothing).
static mut EXEC_WRITABLE_FS: Option<nt_fs::FileSystem> = None;
static WRITABLE_FS_MOUNT_DIRTY: AtomicBool = AtomicBool::new(false);
static WRITABLE_FS_RUNTIME_DIRTY: AtomicBool = AtomicBool::new(false);
static WRITABLE_FS_SNAPSHOT_DIRTY: AtomicBool = AtomicBool::new(false);
static WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED: AtomicBool = AtomicBool::new(false);
// A v2 fold may advance the global WAL base only after any SYSTEM suffix is represented by
// an exact CM checkpoint image. Boot replay can leave such a suffix even before a new mutation.
static SYSTEM_WAL_FOLD_REQUIRED: AtomicBool = AtomicBool::new(false);
/// The mounted filesystem's durable snapshot format, recorded before it is published.
/// Generic checkpoints preserve this format; CM mutations use the v2 WAL when mounted.
static WRITABLE_FS_MOUNTED_WAL_FORMAT: AtomicBool = AtomicBool::new(false);
static WRITABLE_FS_SNAPSHOT_RESTORE_STATE: AtomicU64 = AtomicU64::new(0);
const SNAPSHOT_RESTORE_UNREAD: u64 = 0;
const SNAPSHOT_RESTORE_EMPTY: u64 = 1;
const SNAPSHOT_RESTORE_CONSUMED: u64 = 2;

pub(crate) fn legacy_snapshot_writes_allowed() -> bool {
    !WRITABLE_FS_MOUNTED_WAL_FORMAT.load(Ordering::Acquire)
}

pub(crate) fn system_wal_fold_blocked() -> bool {
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire)
}

pub(crate) fn block_uncertain_snapshot_reserve() {
    WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
}

/// A legacy SYSTEM checkpoint may have changed a snapshot slot before a provider error was
/// reported. Preserve its CM preparation and refuse all later mount writes until boot recovery.
pub(crate) fn block_uncertain_system_checkpoint() {
    block_uncertain_snapshot_reserve();
}

fn note_mounted_snapshot_format(format: nt_fs::SnapshotReadFormat) {
    WRITABLE_FS_MOUNTED_WAL_FORMAT.store(
        matches!(format, nt_fs::SnapshotReadFormat::Wal { .. }),
        Ordering::Release,
    );
}

pub(crate) static WRITABLE_FS_SNAPSHOT_RESTORES: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_RESTORE_GENERATION: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_RESTORE_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_EMPTY_MOUNTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_COMMITS: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_COMMIT_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_SNAPSHOT_WRITE_SECTORS: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_BLOB_COMPACTIONS: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_BLOBS_RECLAIMED: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_BLOB_BYTES_RECLAIMED: AtomicU64 = AtomicU64::new(0);
pub(crate) static WRITABLE_FS_BLOB_COMPACTION_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Statistics — every one of these is a REAL operation that went through the `Zw*` surface.
pub(crate) static OVERLAY_CREATES: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_DIRS_CREATED: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_OPENS: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_WRITES: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_READS: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_BYTES_READ: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_DIR_QUERIES: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_DIR_ENTRIES: AtomicU64 = AtomicU64::new(0);
/// Why an `NtQueryDirectoryFile` was refused BEFORE it reached a volume, so the enumeration
/// frontier is measured rather than guessed (both statuses map to `GetLastError() == 998`).
pub(crate) static QUERY_DIR_MISALIGNED: AtomicU64 = AtomicU64::new(0);
pub(crate) static QUERY_DIR_IOSB_UNREACHABLE: AtomicU64 = AtomicU64::new(0);
pub(crate) static QUERY_DIR_BUFFER_UNREACHABLE: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_SET_INFO: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_ATTR_QUERIES: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_ATTR_HITS: AtomicU64 = AtomicU64::new(0);
pub(crate) static OVERLAY_CLOSES: AtomicU64 = AtomicU64::new(0);
/// The executive's own mount-time self-test result (see [`selftest`]): a bitmask of the checks that
/// passed, all through the real `Zw*` surface on a scratch subtree that is then deleted.
pub(crate) static OVERLAY_SELFTEST: AtomicU64 = AtomicU64::new(0);
/// ★ winlogon really created the PROFILES ROOT (`C:\Profiles`) — `userenv!CreateUserProfileExW`'s
/// `CreateDirectoryW(szProfilesPath)` at `profile.c:929`, the exact call that used to return
/// `Error: 1`. Counted only for a create that returned `FILE_CREATED` to pi 2 (winlogon).
pub(crate) static PROFILE_ROOT_CREATED: AtomicU64 = AtomicU64::new(0);
/// ★ …and the PER-USER profile directory under it (`C:\Profiles\Administrator`) —
/// `CreateDirectoryW(szUserProfilePath)` at `profile.c:963`, which is only reachable once the root
/// create succeeded AND `ProfileList\DefaultUserProfile` read back from the real SOFTWARE hive.
pub(crate) static PROFILE_USER_DIR_CREATED: AtomicU64 = AtomicU64::new(0);

/// ★ …and winlogon's `CreateDirectoryW(szProfilesPath)` genuinely COLLIDING with a profiles root
/// that already exists — `profile.c:929`'s `ERROR_ALREADY_EXISTS` arm, which is what the call
/// returns on any installed system whose setup already made the profiles directory. Counted only
/// for a `FILE_CREATE` that the volume really refused with `STATUS_OBJECT_NAME_COLLISION`, so it is
/// evidence of REAL volume state, never of a fabricated success.
pub(crate) static PROFILE_ROOT_COLLIDED: AtomicU64 = AtomicU64::new(0);

/// ★ …and `CopyDirectory` itself: the directories and files winlogon created BELOW
/// `C:\Profiles\<user>`, which only its recursion over the `Default User` source can produce.
pub(crate) static PROFILE_COPY_DIRS: AtomicU64 = AtomicU64::new(0);
pub(crate) static PROFILE_COPY_FILES: AtomicU64 = AtomicU64::new(0);

/// Classify winlogon's writable-volume DIRECTORY create as the profiles root / a per-user profile
/// directory, for the winlogon profile-creation spec. Pure path shape, no name allow-list.
/// `created` distinguishes a `FILE_CREATED` from a real `STATUS_OBJECT_NAME_COLLISION` refusal.
pub(crate) fn note_directory_create(pi: usize, relative: &[u8], created: bool) {
    if pi != 2 {
        return;
    }
    let depth = relative.iter().filter(|byte| **byte == b'\\').count();
    if relative == crate::installed_layout::USERS {
        if created {
            PROFILE_ROOT_CREATED.fetch_add(1, Ordering::Relaxed);
        } else {
            PROFILE_ROOT_COLLIDED.fetch_add(1, Ordering::Relaxed);
        }
    } else if created && depth == 1 && relative.starts_with(crate::installed_layout::USERS_PREFIX) {
        PROFILE_USER_DIR_CREATED.fetch_add(1, Ordering::Relaxed);
    } else if created && depth >= 2 && relative.starts_with(crate::installed_layout::USERS_PREFIX) {
        // Anything DEEPER than `profiles\<user>` can only have been made by `CopyDirectory`'s
        // recursion (`userenv!directory.c:124  CreateDirectoryExW(src, dst, NULL)`) — winlogon
        // itself only ever creates the root and the per-user directory.
        PROFILE_COPY_DIRS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Note a winlogon FILE create/write inside the per-user profile tree — `CopyDirectory`'s
/// `CopyFileW` leg (`directory.c:139`). Only pi 2, only under `profiles\<something>\`, and only for
/// a create that the volume really reported as `FILE_CREATED`.
pub(crate) fn note_profile_file_create(pi: usize, relative: &[u8]) {
    if pi == 2
        && relative.starts_with(crate::installed_layout::USERS_PREFIX)
        && relative.iter().filter(|byte| **byte == b'\\').count() >= 2
    {
        PROFILE_COPY_FILES.fetch_add(1, Ordering::Relaxed);
    }
}


fn mark_runtime_dirty() {
    WRITABLE_FS_RUNTIME_DIRTY.store(true, Ordering::Release);
}

fn mark_snapshot_dirty() {
    mark_runtime_dirty();
    WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
}

fn create_information_changes_volume(information: u32) -> bool {
    information == nt_fs::FILE_CREATED
        || information == nt_fs::FILE_OVERWRITTEN
        || information == nt_fs::FILE_SUPERSEDED
}

fn snapshot_store_error_status(err: nt_fs::SnapshotBlockStoreError) -> u32 {
    match err {
        nt_fs::SnapshotBlockStoreError::OutOfMemory
        | nt_fs::SnapshotBlockStoreError::OutOfSpace
        | nt_fs::SnapshotBlockStoreError::InvalidGeometry => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        nt_fs::SnapshotBlockStoreError::Io | nt_fs::SnapshotBlockStoreError::Corrupt => 0xC000_0001,
    }
}

fn print_snapshot_store_error(err: nt_fs::SnapshotBlockStoreError) {
    print_str(match err {
        nt_fs::SnapshotBlockStoreError::InvalidGeometry => b"invalid-geometry",
        nt_fs::SnapshotBlockStoreError::OutOfSpace => b"out-of-space",
        nt_fs::SnapshotBlockStoreError::Io => b"io",
        nt_fs::SnapshotBlockStoreError::Corrupt => b"corrupt",
        nt_fs::SnapshotBlockStoreError::OutOfMemory => b"out-of-memory",
    });
}

unsafe fn restore_snapshot_volume(
    dev: &mut snapshot_storage::Lease,
) -> Result<Option<(nt_fs::FileSystem, nt_fs::StoredSnapshotMetadata)>, u32> {
    let store = dev.store();
    // A WAL-bearing snapshot cannot be published until its committed suffix has been
    // authenticated and replayed. The current native writer still uses legacy snapshots;
    // the pre-replay reader also admits a complete, empty-WAL v2 baseline.
    match nt_fs::FileSystem::restore_volume_snapshot_before_wal_replay_from_store(&store, dev) {
        Ok(Some((fs, metadata))) => Ok(Some((fs, metadata))),
        Ok(None) => {
            WRITABLE_FS_SNAPSHOT_EMPTY_MOUNTS.fetch_add(1, Ordering::Relaxed);
            print_str(b"[writable-fs-snapshot] no stored snapshot in reserve sectors=");
            print_u64(dev.sector_count());
            print_str(b"\n");
            Ok(None)
        }
        Err(err) => {
            WRITABLE_FS_SNAPSHOT_FAILURES.fetch_add(1, Ordering::Relaxed);
            print_str(b"[writable-fs-snapshot] restore failed err=");
            print_snapshot_store_error(err);
            print_str(b"\n");
            Err(snapshot_store_error_status(err))
        }
    }
}

unsafe fn restore_snapshot_volume_once(
) -> Result<Option<(nt_fs::FileSystem, nt_fs::StoredSnapshotMetadata)>, u32> {
    let mut dev = snapshot_storage::acquire()?;
    match WRITABLE_FS_SNAPSHOT_RESTORE_STATE.load(Ordering::Acquire) {
        SNAPSHOT_RESTORE_EMPTY => return Ok(None),
        SNAPSHOT_RESTORE_UNREAD => {}
        // A previously returned volume is not evidence of absence if its caller lost installation.
        _ => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
    let result = restore_snapshot_volume(&mut dev);
    if let Ok(restored) = &result {
        WRITABLE_FS_SNAPSHOT_RESTORE_STATE.store(
            if restored.is_some() { SNAPSHOT_RESTORE_CONSUMED } else { SNAPSHOT_RESTORE_EMPTY },
            Ordering::Release,
        );
    }
    result
}

/// Repair a boot-visible transition under the original reserve lease. Any failed write keeps
/// the owner unavailable until a later boot can prove the durable state again.
fn repair_boot_snapshot_baseline(
    store: nt_fs::SnapshotBlockStore,
    dev: snapshot_storage::Lease,
    state: nt_fs::BootSnapshotRecovery,
) -> Result<snapshot_storage::Lease, u32> {
    match state {
        nt_fs::BootSnapshotRecovery::Ready => Ok(dev),
        nt_fs::BootSnapshotRecovery::InterruptedEmptyBaseline { incarnation } => {
            let range = snapshot_storage::owned_wal_region(dev)
                .map_err(|(status, _lease)| status)?;
            let mut wal = nt_fs::RegistryWal::recover(range, incarnation)
                .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
            if wal.state() == nt_fs::RegistryWalState::RecoveredUncommitted {
                if wal.clear_recovered_tail().is_err() {
                    core::mem::forget(wal);
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
            }
            let verified = match wal.into_verified_device() {
                Ok(verified) => verified.into_full_device(),
                Err(wal) => {
                    core::mem::forget(wal);
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
            };
            let mut repair = nt_fs::WalSnapshotBaselineRepair::admit(store, verified)
                .map_err(|(_error, _verified)| nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
            if let Err(error) = repair.repair() {
                core::mem::forget(repair);
                return Err(snapshot_store_error_status(error));
            }
            Ok(repair.into_verified_device()
                .expect("completed WAL baseline repair")
                .into_device())
        }
        nt_fs::BootSnapshotRecovery::Resetting => {
            let (wal_start, wal_sectors) = snapshot_storage::wal_bounds(&dev)?;
            let mut rollover = nt_fs::WalSnapshotEpochRollover::resume(
                store, dev, wal_start, wal_sectors,
            ).map_err(|(error, _lease)| snapshot_store_error_status(error))?;
            if let Err(error) = rollover.finish() {
                core::mem::forget(rollover);
                return Err(snapshot_store_error_status(error));
            }
            match rollover.into_device() {
                Ok(dev) => Ok(dev),
                Err(rollover) => {
                    core::mem::forget(rollover);
                    Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST)
                }
            }
        }
    }
}

/// Return the decoded boot volume with the exact reserve lease that selected its metadata.
/// The caller owns that lease through WAL recovery and CM import.
unsafe fn restore_boot_snapshot_volume_once(
) -> Result<Option<(nt_fs::FileSystem, nt_fs::StoredSnapshotMetadata, snapshot_storage::Lease)>, u32> {
    let mut dev = snapshot_storage::acquire()?;
    match WRITABLE_FS_SNAPSHOT_RESTORE_STATE.load(Ordering::Acquire) {
        SNAPSHOT_RESTORE_EMPTY => return Ok(None),
        SNAPSHOT_RESTORE_UNREAD => {}
        _ => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
    let store = dev.store();
    let state = store.boot_recovery_state(&mut dev)
        .map_err(snapshot_store_error_status)?;
    dev = repair_boot_snapshot_baseline(store, dev, state)?;
    let restored = nt_fs::FileSystem::restore_volume_snapshot_with_metadata_from_store(&store, &mut dev)
        .map_err(|error| {
            WRITABLE_FS_SNAPSHOT_FAILURES.fetch_add(1, Ordering::Relaxed);
            print_str(b"[writable-fs-snapshot] boot restore failed err=");
            print_snapshot_store_error(error);
            print_str(b"\n");
            snapshot_store_error_status(error)
        })?;
    WRITABLE_FS_SNAPSHOT_RESTORE_STATE.store(
        if restored.is_some() { SNAPSHOT_RESTORE_CONSUMED } else { SNAPSHOT_RESTORE_EMPTY },
        Ordering::Release,
    );
    if restored.is_none() {
        WRITABLE_FS_SNAPSHOT_EMPTY_MOUNTS.fetch_add(1, Ordering::Relaxed);
        print_str(b"[writable-fs-snapshot] no stored snapshot in reserve sectors=");
        print_u64(dev.sector_count());
        print_str(b"\n");
    }
    Ok(restored.map(|(fs, metadata)| (fs, metadata, dev)))
}

unsafe fn snapshot_reserve_available() -> bool {
    let Some(fat) = crate::fs_loader::exec_fs() else {
        return false;
    };
    crate::fs_loader::writable_snapshot_reserve(&fat).is_some()
}

fn note_restored_snapshot(generation: u64, bytes: usize, nodes: usize) {
    WRITABLE_FS_SNAPSHOT_RESTORES.fetch_add(1, Ordering::Relaxed);
    WRITABLE_FS_SNAPSHOT_RESTORE_GENERATION.store(generation, Ordering::Relaxed);
    WRITABLE_FS_SNAPSHOT_RESTORE_BYTES.store(bytes as u64, Ordering::Relaxed);
    print_str(b"[writable-fs-snapshot] restored generation=");
    print_u64(generation);
    print_str(b" bytes=");
    print_u64(bytes as u64);
    print_str(b" nodes=");
    print_u64(nodes as u64);
    print_str(b"\n");
}

static mut WRITABLE_MOUNT_ID: Option<nt_memory_manager::SectionMountId> = None;

unsafe fn install_writable_fs(mut fs: nt_fs::FileSystem, restored: bool) -> Result<(), u32> {
    if registry_journal::owns_volume() {
        return Err(snapshot_storage::BUSY);
    }
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_some() {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let mount = crate::mounted_volume::allocate_mount_id()?;
    let timestamps_initialized = fs.initialize_timestamps(nt_system_time_100ns());
    selftest(&mut fs);
    let provisioned = provision_missing_installed_sources(&mut fs);
    let slot = &mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS);
    *slot = Some(fs);
    *core::ptr::addr_of_mut!(WRITABLE_MOUNT_ID) = Some(mount);
    mark_runtime_dirty();
    WRITABLE_FS_MOUNT_DIRTY.store(true, Ordering::Release);
    if timestamps_initialized || provisioned || !restored {
        mark_snapshot_dirty();
    }
    Ok(())
}

enum SnapshotCommitFailure {
    Unentered(u32),
    Entered(u32),
}

unsafe fn checkpoint_volume_snapshot(
    dev: &mut snapshot_storage::Lease,
    wal_manifest: Option<nt_fs::WalSnapshotManifest>,
    captured_image: Option<&[u8]>,
) -> Result<(u64, usize), SnapshotCommitFailure> {
    let Some(fs) = (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).as_ref() else {
        return Err(SnapshotCommitFailure::Unentered(nt_fs::STATUS_INVALID_HANDLE));
    };
    let store = dev.store();
    print_str(b"[writable-fs-snapshot] dirty commit begin nodes=");
    print_u64(fs.node_count() as u64);
    print_str(b" reserve-sectors=");
    print_u64(dev.sector_count());
    print_str(b" written-sectors=");
    print_u64(WRITABLE_FS_SNAPSHOT_WRITE_SECTORS.load(Ordering::Relaxed));
    print_str(b"\n");
    let result = match wal_manifest {
        Some(manifest) => {
            let image = captured_image.ok_or(SnapshotCommitFailure::Unentered(
                nt_fs::STATUS_INVALID_DEVICE_REQUEST,
            ))?;
            // The captured payload is already durable. The synchronous cursor's scratch must
            // also survive the caller's nearly full transient syscall scope. Construct it before
            // the first physical request so an allocation refusal can return the exact authority.
            let _durable = crate::allocator::enter_durable();
            let commit = nt_fs::AsyncSnapshotCommit::new(
                store, image, manifest, dev.sector_size(), dev.sector_count(),
            ).map_err(|error| SnapshotCommitFailure::Unentered(snapshot_store_error_status(error)))?;
            commit.run_sync(dev).map(|generation| (generation, image.len()))
        }
        None => fs.commit_volume_snapshot(&store, dev),
    };
    match result {
        Ok((generation, bytes)) => Ok((generation, bytes)),
        Err(err) => {
            print_str(b"[writable-fs-snapshot] commit failed err=");
            print_snapshot_store_error(err);
            print_str(b"\n");
            Err(SnapshotCommitFailure::Entered(snapshot_store_error_status(err)))
        }
    }
}

/// Prove the mounted SYSTEM WAL has a complete, paired durable prefix. Every v2 mutation
/// crosses its marker and both anchor barriers before its caller receives success; the reserve
/// lease excludes a mutation still crossing those barriers. NtFlushKey needs this durability
/// fence even when no full snapshot fold is due.
pub(crate) unsafe fn verify_durable_system_wal() -> Result<(), u32> {
    let native = crate::fs_loader::exec_fs_mount_identity()
        .and_then(crate::fs_loader::exec_block_route_kind)
        == Some(nt_fs::BlockSourceKind::Native);
    if native {
        if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none() {
            return Err(nt_fs::STATUS_DEVICE_NOT_READY);
        }
    } else {
        ensure_mounted()?;
    }
    if legacy_snapshot_writes_allowed() || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let mut lease = snapshot_storage::acquire()?;
    let result = if native {
        snapshot_storage::check_cached_wal_fence(&lease)
    } else {
        snapshot_storage::peek_wal_continuation(&mut lease).map(|_| ())
    };
    result.map_err(|status| {
        // An acquired reserve with no matching in-process token contradicts the completed
        // mutation/boot publication contract. No later writer may guess the WAL prefix.
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        status
    })
}

/// Terminal quiesce may inspect durability but cannot start native snapshot I/O: its service
/// receive loop has ended and would never deliver the provider completions. Hold the reserve
/// while checking both the clean volume bit and the exact paired WAL publication.
pub(crate) unsafe fn with_clean_v2_volume_at_quiesce<F>(verify_hives: F) -> Result<(), u32>
where
    F: FnOnce() -> Result<(), u32>,
{
    let native = crate::fs_loader::exec_fs_mount_identity()
        .and_then(crate::fs_loader::exec_block_route_kind)
        == Some(nt_fs::BlockSourceKind::Native);
    if native {
        if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none() {
            return Err(nt_fs::STATUS_DEVICE_NOT_READY);
        }
    } else {
        ensure_mounted()?;
    }
    if legacy_snapshot_writes_allowed() || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let mut lease = snapshot_storage::acquire()?;
    if WRITABLE_FS_SNAPSHOT_DIRTY.load(Ordering::Acquire) {
        return Err(snapshot_storage::BUSY);
    }
    verify_hives()?;
    let result = if native {
        snapshot_storage::check_cached_wal_fence(&lease)
    } else {
        snapshot_storage::peek_wal_continuation(&mut lease).map(|_| ())
    };
    result.map_err(|status| {
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        status
    })
}

/// A failed pre-write capture has no disk effect; put the exact paired proof and WAL token back
/// under the same mount lease before another writer can acquire it.
fn restore_unwritten_checkpoint_authority(
    dev: snapshot_storage::Lease,
    authority: Option<(nt_fs::RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot)>,
    status: u32,
) -> u32 {
    if let Some((token, pair)) = authority {
        if let Err((error, token, pair)) = snapshot_storage::install_wal_continuation(&dev, token, pair) {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(token);
            core::mem::forget(pair);
            core::mem::forget(dev);
            return error;
        }
    }
    drop(dev);
    status
}

/// Commit pending volume bytes. `Ok(true)` means a new durable snapshot was published, while
/// `Ok(false)` means the volume was already clean.
pub(crate) unsafe fn checkpoint_dirty_volume() -> Result<bool, u32> {
    if crate::fs_loader::exec_fs_mount_identity()
        .and_then(crate::fs_loader::exec_block_route_kind)
        == Some(nt_fs::BlockSourceKind::Native) {
        return native_checkpoint::checkpoint_dirty_native();
    }
    let wal_format = !legacy_snapshot_writes_allowed();
    if WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    // Even a clean observation needs exclusion: another owner may have cleared the bit but not
    // yet finished its barrier. Refusal cannot consume dirty state or authorize caller completion.
    let mut dev = snapshot_storage::acquire()?;
    if !WRITABLE_FS_SNAPSHOT_DIRTY.swap(false, Ordering::AcqRel) {
        return Ok(false);
    }
    let (wal_manifest, authority) = if wal_format {
        match snapshot_storage::take_wal_continuation(&mut dev) {
            Ok((token, pair, manifest)) => (Some(manifest), Some((token, pair))),
            Err(status) => {
                WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                return Err(status);
            }
        }
    } else {
        (None, None)
    };
    // Capture the v2 payload before physical I/O can reenter the executive. A second pass over
    // the live tree could produce different length or CRC after the first payload sectors land.
    let captured_image = if wal_format {
        let Some(fs) = (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).as_ref() else {
            WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
            return Err(restore_unwritten_checkpoint_authority(
                dev, authority, nt_fs::STATUS_INVALID_HANDLE,
            ));
        };
        match snapshot_capture::CapturedSnapshot::capture(&dev, fs) {
            Ok(image) => Some(image),
            Err(status) => {
                WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
                return Err(restore_unwritten_checkpoint_authority(dev, authority, status));
            }
        }
    } else {
        None
    };
    match checkpoint_volume_snapshot(
        &mut dev,
        wal_manifest,
        captured_image.as_ref().map(snapshot_capture::CapturedSnapshot::as_slice),
    ) {
        Ok((generation, bytes)) => {
            if let Some((token, old_pair)) = authority {
                let pair = match dev.store().verify_paired_wal_snapshot(&mut dev) {
                    Ok(pair) if pair.anchor() == token.anchor() => pair,
                    Ok(_) => {
                        WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
                        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                        core::mem::forget(token);
                        core::mem::forget(old_pair);
                        core::mem::forget(dev);
                        return Err(nt_fs::STATUS_DATA_ERROR);
                    }
                    Err(error) => {
                        WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
                        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                        core::mem::forget(token);
                        core::mem::forget(old_pair);
                        core::mem::forget(dev);
                        return Err(snapshot_store_error_status(error));
                    }
                };
                drop(old_pair);
                if let Err((status, token, pair)) = snapshot_storage::install_wal_continuation(&dev, token, pair) {
                    WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
                    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                    core::mem::forget(token);
                    core::mem::forget(pair);
                    core::mem::forget(dev);
                    return Err(status);
                }
            }
            WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(bytes as u64, Ordering::Relaxed);
            print_str(b"[writable-fs-snapshot] committed generation=");
            print_u64(generation);
            print_str(b" bytes=");
            print_u64(bytes as u64);
            print_str(b"\n");
            Ok(true)
        }
        Err(SnapshotCommitFailure::Unentered(status)) => {
            WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
            Err(restore_unwritten_checkpoint_authority(dev, authority, status))
        }
        Err(SnapshotCommitFailure::Entered(status)) => {
            WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
            WRITABLE_FS_SNAPSHOT_FAILURES.fetch_add(1, Ordering::Relaxed);
            // Either snapshot format can have changed a slot before reporting failure.
            // Retain the physical reserve and let boot recovery choose the durable image.
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            if let Some((token, pair)) = authority {
                core::mem::forget(token);
                core::mem::forget(pair);
            }
            core::mem::forget(dev);
            print_str(b"[writable-fs-snapshot] dirty checkpoint retained after status=0x");
            print_hex(status);
            print_str(b"\n");
            Err(status)
        }
    }
}

/// Reclaim immutable blob payloads made unreachable by truncate, replace, or unlink.
///
/// The caller must run this after resetting snapshot scratch and preserve the allocator mark when
/// this returns `true`, because the compacted extent index becomes durable mounted-volume state.
pub(crate) unsafe fn compact_unreferenced_blobs() -> bool {
    let Some(fs) = (*core::ptr::addr_of_mut!(EXEC_WRITABLE_FS)).as_mut() else {
        return false;
    };
    match fs.compact_volume_blobs() {
        Ok(result) => {
            let reclaimed_blobs = result.reclaimed_blobs();
            let reclaimed_bytes = result.reclaimed_bytes();
            if reclaimed_blobs == 0 {
                return false;
            }
            WRITABLE_FS_BLOB_COMPACTIONS.fetch_add(1, Ordering::Relaxed);
            WRITABLE_FS_BLOBS_RECLAIMED.fetch_add(reclaimed_blobs as u64, Ordering::Relaxed);
            WRITABLE_FS_BLOB_BYTES_RECLAIMED.fetch_add(reclaimed_bytes as u64, Ordering::Relaxed);
            print_str(b"[writable-fs] compacted blobs=");
            print_u64(result.blobs_before as u64);
            print_str(b"->");
            print_u64(result.blobs_after as u64);
            print_str(b" bytes=");
            print_u64(result.bytes_before as u64);
            print_str(b"->");
            print_u64(result.bytes_after as u64);
            print_str(b"\n");
            true
        }
        Err(err) => {
            WRITABLE_FS_BLOB_COMPACTION_FAILURES.fetch_add(1, Ordering::Relaxed);
            print_str(b"[writable-fs] blob compaction failed err=");
            print_str(match err {
                nt_fs::MemFsBlobCompactError::CorruptExtent => b"corrupt-extent",
                nt_fs::MemFsBlobCompactError::OutOfMemory => b"out-of-memory",
            });
            print_str(b"\n");
            false
        }
    }
}

pub(crate) fn snapshot_restore_seen() -> bool {
    WRITABLE_FS_SNAPSHOT_RESTORES.load(Ordering::Acquire) != 0
}

fn has_directory_relative(fs: &nt_fs::FileSystem, relative: &[u8]) -> bool {
    fs.query_attributes_relative(relative)
        .is_some_and(|info| info.is_directory)
}

fn append_ascii_utf16_name(
    out: &mut alloc::string::String,
    record: &[u8],
    name_offset: usize,
    name_len: usize,
) -> bool {
    if name_len == 0 || name_len % 2 != 0 || name_offset + name_len > record.len() {
        return false;
    }
    let before = out.len();
    for unit in record[name_offset..name_offset + name_len].chunks_exact(2) {
        if unit[1] != 0 || unit[0] == 0 || unit[0] > 0x7f {
            out.truncate(before);
            return false;
        }
        out.push(unit[0] as char);
    }
    true
}

fn restored_profile_source_tree_stats(fs: &mut nt_fs::FileSystem) -> StagedTreeStats {
    const SOURCE_ROOTS: [&str; 2] = [
        crate::installed_layout::NT_DEFAULT_PROFILE,
        crate::installed_layout::NT_PUBLIC_PROFILE,
    ];
    const DIRECTORY_NAME_OFFSET: usize = 64;
    const FILE_ATTRIBUTES_OFFSET: usize = 56;
    const FILE_NAME_LENGTH_OFFSET: usize = 60;

    let mut stats = StagedTreeStats::default();
    let mut stack: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    for root in SOURCE_ROOTS {
        let Some(info) = fs.query_attributes(root) else {
            continue;
        };
        if info.is_directory {
            stats.dirs += 1;
            stack.push(alloc::string::String::from(root));
        } else {
            stats.files += 1;
            stats.bytes += info.end_of_file;
        }
    }

    while let Some(path) = stack.pop() {
        let dir = fs.zw_create_file(
            &path,
            nt_fs::FILE_READ_DATA,
            0,
            0,
            nt_fs::FILE_OPEN,
            nt_fs::FILE_DIRECTORY_FILE,
        );
        if dir.status != nt_fs::STATUS_SUCCESS {
            continue;
        }

        let mut buffer = [0u8; 4096];
        let mut restart = true;
        loop {
            let result = fs.zw_query_directory_file(
                dir.handle,
                nt_fs::FILE_DIRECTORY_INFORMATION,
                false,
                None,
                restart,
                &mut buffer,
            );
            restart = false;
            if result.status != nt_fs::STATUS_SUCCESS {
                break;
            }

            let mut offset = 0usize;
            loop {
                if offset + DIRECTORY_NAME_OFFSET > result.information {
                    break;
                }
                let next =
                    u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
                let attributes = u32::from_le_bytes(
                    buffer[offset + FILE_ATTRIBUTES_OFFSET..offset + FILE_ATTRIBUTES_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                let name_len = u32::from_le_bytes(
                    buffer[offset + FILE_NAME_LENGTH_OFFSET..offset + FILE_NAME_LENGTH_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                ) as usize;
                let record_end = if next == 0 {
                    result.information
                } else {
                    offset.saturating_add(next).min(result.information)
                };
                if record_end < offset || record_end > buffer.len() {
                    break;
                }
                let record = &buffer[offset..record_end];
                let mut child = path.clone();
                child.push('\\');
                if append_ascii_utf16_name(&mut child, record, DIRECTORY_NAME_OFFSET, name_len) {
                    let name = &child[path.len() + 1..];
                    if name != "." && name != ".." {
                        if attributes & nt_fs::FILE_ATTRIBUTE_DIRECTORY != 0 {
                            stats.dirs += 1;
                            stack.push(child);
                        } else {
                            stats.files += 1;
                            if let Some(info) = fs.query_attributes(&child) {
                                stats.bytes += info.end_of_file;
                            }
                        }
                    }
                }
                if next == 0 {
                    break;
                }
                offset += next;
            }
        }
        let _ = fs.zw_close(dir.handle);
    }

    stats
}

fn refresh_live_profile_source_proofs(fs: &mut nt_fs::FileSystem) {
    let stats = restored_profile_source_tree_stats(fs);
    PROFILE_SOURCE_DIRS.store(stats.dirs, Ordering::Relaxed);
    PROFILE_SOURCE_FILES.store(stats.files, Ordering::Relaxed);
    PROFILE_SOURCE_BYTES.store(stats.bytes, Ordering::Relaxed);
    PROFILE_SOURCE_PROBE_OK.store(
        fs.query_attributes(DEFAULT_USER_PROBE_FILE)
            .is_some_and(|info| info.is_directory) as u64,
        Ordering::Relaxed,
    );
    PROFILE_SOURCE_ENTRIES.store(
        count_entries(fs, DEFAULT_USER_PROFILE_DIR),
        Ordering::Relaxed,
    );
    let ntuser_len = hive_image_len_on(fs, DEFAULT_USER_NTUSER_DAT);
    if ntuser_len != 0 {
        NTUSER_DAT_PROVISIONED.store(ntuser_len as u64, Ordering::Relaxed);
    }
}

fn refresh_restored_config_proofs(fs: &nt_fs::FileSystem) {
    CONFIG_SOURCE_SYSTEM_HIVE_OK.store(
        (hive_image_len_on(fs, CONFIG_SYSTEM_HIVE_PATH) != 0) as u64,
        Ordering::Relaxed,
    );
    CONFIG_SOURCE_SOFTWARE_HIVE_OK.store(
        (hive_image_len_on(fs, CONFIG_SOFTWARE_HIVE_PATH) != 0) as u64,
        Ordering::Relaxed,
    );
}

unsafe fn provision_missing_installed_sources(fs: &mut nt_fs::FileSystem) -> bool {
    let mut changed = false;
    if PROVISION_DEFAULT_USER_PROFILE && !has_directory_relative(fs, PROFILES_VOLUME_ROOT_RELATIVE)
    {
        let before = fs.node_count();
        provision_staged_profiles(fs);
        changed |= fs.node_count() != before;
    } else {
        refresh_live_profile_source_proofs(fs);
    }
    if !has_directory_relative(fs, CONFIG_VOLUME_ROOT_RELATIVE) {
        let before = fs.node_count();
        provision_staged_config(fs);
        changed |= fs.node_count() != before;
    } else {
        refresh_restored_config_proofs(fs);
    }
    if fs
        .query_attributes_relative(BOOT_STATUS_VOLUME_RELATIVE)
        .is_none()
    {
        changed |= fs.provision_file(BOOT_STATUS_PATH, &initial_boot_status_data());
    }
    changed
}

/// The live writable volume, mounting it on first use. Admission failure is never file absence.
///
/// # Safety
/// Single-threaded executive; the returned reference must not outlive the calling syscall service.
unsafe fn writable_fs() -> Result<&'static mut nt_fs::FileSystem, u32> {
    if registry_journal::owns_volume() {
        return Err(snapshot_storage::BUSY);
    }
    if !WRITABLE_OVERLAY_MOUNTED {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none() {
        let (fs, restored) = match restore_snapshot_volume_once() {
            Ok(Some((fs, metadata))) => {
                note_restored_snapshot(metadata.generation, metadata.payload_len, fs.node_count());
                note_mounted_snapshot_format(metadata.format);
                (fs, true)
            }
            Ok(None) => (nt_fs::FileSystem::new(nt_fs::MemFs::new()), false),
            Err(snapshot_storage::BUSY) => return Err(snapshot_storage::BUSY),
            Err(status) => {
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                print_str(
                    b"[writable-fs-snapshot] refusing writable mount after restore status=0x",
                );
                print_hex(status);
                print_str(b"\n");
                return Err(status);
            }
        };
        if let Err(status) = install_writable_fs(fs, restored) {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return Err(status);
        }
    }
    let fs = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
        .as_mut()
        .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    fs.set_current_time_100ns(nt_system_time_100ns());
    Ok(fs)
}

/// Mount without lending filesystem ownership outside this module.
pub(crate) unsafe fn ensure_mounted() -> Result<(), u32> {
    writable_fs().map(|_| ())
}

/// A non-mounting namespace observation. An unread or unsuccessfully installed snapshot is not
/// an absent upper layer. Only a disabled overlay or a confirmed empty reserve permits that result.
unsafe fn mounted_namespace_fs() -> Result<Option<&'static mut nt_fs::FileSystem>, u32> {
    if registry_journal::owns_volume() {
        return Err(snapshot_storage::BUSY);
    }
    if !WRITABLE_OVERLAY_MOUNTED {
        return Ok(None);
    }
    if WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if let Some(fs) = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS)).as_mut() {
        fs.set_current_time_100ns(nt_system_time_100ns());
        return Ok(Some(fs));
    }
    if WRITABLE_FS_SNAPSHOT_RESTORE_STATE.load(Ordering::Acquire) == SNAPSHOT_RESTORE_EMPTY {
        Ok(None)
    } else {
        Err(nt_fs::STATUS_DEVICE_NOT_READY)
    }
}

pub(crate) enum BootSystemPersistence {
    Absent,
    Restored(RestoredBootSystem),
}

enum BootSystemReserveOwner {
    Legacy(snapshot_storage::Lease),
    Wal {
        store: nt_fs::SnapshotBlockStore,
        verified: nt_fs::RegistryWalVerifiedDevice<snapshot_storage::Lease>,
    },
    Continuation {
        lease: snapshot_storage::Lease,
        token: nt_fs::RegistryWalContinuation,
    },
}

pub(crate) struct RestoredBootSystem {
    pub(crate) snapshot_generation: u64,
    pub(crate) snapshot_bytes: usize,
    pub(crate) primary: Option<alloc::vec::Vec<u8>>,
    pub(crate) log: alloc::vec::Vec<u8>,
    pub(crate) wal_suffix: Option<nt_hive_regf::BootSystemWalSuffix>,
    fs: Option<nt_fs::FileSystem>,
    format: nt_fs::SnapshotReadFormat,
    _lease: Option<BootSystemReserveOwner>,
}

fn replace_boot_file(fs: &mut nt_fs::FileSystem, path: &str, bytes: alloc::vec::Vec<u8>) -> Result<(), u32> {
    let file = fs.zw_create_file(
        path,
        nt_fs::FILE_WRITE_DATA | nt_fs::SYNCHRONIZE,
        0,
        0,
        nt_fs::FILE_OPEN_IF,
        nt_fs::FILE_NON_DIRECTORY_FILE,
    );
    if file.status != nt_fs::STATUS_SUCCESS {
        return Err(file.status);
    }
    let status = fs.replace_file_data_owned(file.handle, bytes);
    let status = if status == nt_fs::STATUS_SUCCESS {
        fs.zw_flush_buffers_file(file.handle)
    } else {
        status
    };
    let _ = fs.zw_close(file.handle);
    if status == nt_fs::STATUS_SUCCESS { Ok(()) } else { Err(status) }
}

fn fold_boot_system_sidecar(fs: &mut nt_fs::FileSystem, composed_image: &[u8]) -> Result<(), u32> {
    let mut primary = alloc::vec::Vec::new();
    primary.try_reserve_exact(composed_image.len())
        .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    primary.extend_from_slice(composed_image);
    replace_boot_file(fs, CONFIG_SYSTEM_HIVE_PATH, primary)?;
    let log_path = alloc::format!("{}.LOG", CONFIG_SYSTEM_HIVE_PATH);
    replace_boot_file(fs, &log_path, alloc::vec::Vec::new())
}

/// Boot cutover is admitted only after native mutation, flush, and shutdown paths use the
/// retained v2 WAL owner. A caller must finish the baseline before importing SYSTEM into CM.
pub(crate) struct BootWalCutoverAdmission { _sealed: () }

pub(crate) fn boot_wal_cutover_admission() -> BootWalCutoverAdmission {
    BootWalCutoverAdmission { _sealed: () }
}

fn publish_boot_wal_continuation(
    mut lease: snapshot_storage::Lease,
    token: nt_fs::RegistryWalContinuation,
) -> Result<(), BootSystemRestoreError> {
    let pair = match lease.store().verify_paired_wal_snapshot(&mut lease) {
        Ok(pair) if pair.anchor() == token.anchor() => pair,
        Ok(_) => {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(token);
            core::mem::forget(lease);
            return Err(BootSystemRestoreError::Snapshot(nt_fs::STATUS_DATA_ERROR));
        }
        Err(error) => {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(token);
            core::mem::forget(lease);
            return Err(BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)));
        }
    };
    if let Err((status, token, pair)) = snapshot_storage::install_wal_continuation(&lease, token, pair) {
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        core::mem::forget(token);
        core::mem::forget(pair);
        core::mem::forget(lease);
        return Err(BootSystemRestoreError::Snapshot(status));
    }
    drop(lease);
    Ok(())
}

/// First boot has no legacy snapshot to migrate. Install the composed SYSTEM image into a new
/// volume and commit both empty-WAL v2 slots under one verified reserve lease before publication.
pub(crate) unsafe fn initialize_empty_boot_system_wal(
    image: &[u8],
    _admission: BootWalCutoverAdmission,
) -> Result<u64, BootSystemRestoreError> {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    // The fresh MemFs has no Config or Profiles parents. Stage the installed source tree into
    // the same image that becomes the first durable baseline, then replace its SYSTEM primary.
    provision_missing_installed_sources(&mut fs);
    fold_boot_system_sidecar(&mut fs, image).map_err(BootSystemRestoreError::Snapshot)?;
    let lease = snapshot_storage::acquire().map_err(BootSystemRestoreError::Snapshot)?;
    snapshot_storage::wal_bounds(&lease).map_err(BootSystemRestoreError::Snapshot)?;
    let store = lease.store();
    let range = snapshot_storage::owned_wal_region(lease)
        .map_err(|(status, _lease)| BootSystemRestoreError::Snapshot(status))?;
    let wal = nt_fs::RegistryWal::recover(range, 1).map_err(BootSystemRestoreError::Wal)?;
    if wal.state() != nt_fs::RegistryWalState::Ready
        || wal.settled_anchor() != Some(nt_fs::WalSnapshotAnchor {
            incarnation: 1, serial: 0, end_lba: 0,
        })
    {
        core::mem::forget(wal);
        return Err(BootSystemRestoreError::Wal(nt_fs::RegistryWalError::InvalidState));
    }
    let verified = match wal.into_verified_device() {
        Ok(verified) => verified.into_full_device(),
        Err(wal) => {
            core::mem::forget(wal);
            return Err(BootSystemRestoreError::Wal(nt_fs::RegistryWalError::InvalidState));
        }
    };
    let mut initialization = nt_fs::WalSnapshotBaselineRepair::admit(store, verified)
        .map_err(|(error, _verified)| BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)))?;
    let generation = match initialization.initialize(&fs) {
        Ok(generation) => generation,
        Err(error) => {
            core::mem::forget(initialization);
            return Err(BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)));
        }
    };
    let (lease, token) = initialization.into_continuation()
        .expect("completed empty WAL initialization");
    publish_boot_wal_continuation(lease, token)?;
    note_mounted_snapshot_format(nt_fs::SnapshotReadFormat::Wal {
        selected_base_serial: 0,
        anchor: nt_fs::WalSnapshotAnchor { incarnation: 1, serial: 0, end_lba: 0 },
    });
    if install_writable_fs(fs, true).is_err() {
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        return Err(BootSystemRestoreError::MountBlocked);
    }
    Ok(generation)
}

impl RestoredBootSystem {
    pub(crate) fn migrate_composed_boot_system(
        &mut self,
        composed_image: &[u8],
        _admission: BootWalCutoverAdmission,
    ) -> Result<(), BootSystemRestoreError> {
        let fs = self.fs.as_mut().expect("unpublished boot filesystem");
        if self.format == nt_fs::SnapshotReadFormat::Legacy {
            let BootSystemReserveOwner::Legacy(lease) = self._lease.take()
                .expect("retained boot reserve lease") else {
                unreachable!("legacy snapshot has a legacy reserve owner")
            };
            snapshot_storage::wal_bounds(&lease)
                .map_err(BootSystemRestoreError::Snapshot)?;
                fold_boot_system_sidecar(fs, composed_image)
                    .map_err(BootSystemRestoreError::Snapshot)?;
                let store = lease.store();
                let range = snapshot_storage::owned_wal_region(lease)
                    .map_err(|(status, _lease)| BootSystemRestoreError::Snapshot(status))?;
                let wal = nt_fs::RegistryWal::recover(range, 1)
                    .map_err(BootSystemRestoreError::Wal)?;
                if wal.state() != nt_fs::RegistryWalState::Ready
                    || wal.settled_anchor() != Some(nt_fs::WalSnapshotAnchor {
                        incarnation: 1, serial: 0, end_lba: 0,
                    })
                {
                    core::mem::forget(wal);
                    return Err(BootSystemRestoreError::Wal(nt_fs::RegistryWalError::InvalidState));
                }
                let verified = match wal.into_verified_device() {
                    Ok(verified) => verified.into_full_device(),
                    Err(wal) => {
                        core::mem::forget(wal);
                        return Err(BootSystemRestoreError::Wal(nt_fs::RegistryWalError::InvalidState));
                    }
                };
                let mut migration = nt_fs::WalSnapshotBaselineRepair::admit(
                    store,
                    verified,
                ).map_err(|(error, _verified)| BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)))?;
                let generation = match migration.migrate(fs) {
                    Ok(generation) => generation,
                    Err(error) => {
                        core::mem::forget(migration);
                        return Err(BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)));
                    }
                };
                let (lease, token) = migration.into_continuation()
                    .expect("completed WAL baseline migration");
                self._lease = Some(BootSystemReserveOwner::Continuation { lease, token });
                self.snapshot_generation = generation;
                self.format = nt_fs::SnapshotReadFormat::Wal {
                    selected_base_serial: 0,
                    anchor: nt_fs::WalSnapshotAnchor { incarnation: 1, serial: 0, end_lba: 0 },
                };
        }
        Ok(())
    }

    /// Publish only after the caller has semantically composed and encoded the CM hive.
    pub(crate) unsafe fn publish(mut self) -> Result<(), BootSystemRestoreError> {
        match self._lease.take() {
            Some(BootSystemReserveOwner::Wal { store, verified }) => {
                let mut update = match nt_fs::WalSnapshotAnchorUpdate::admit_verified_wal(store, verified) {
                    Ok(update) => update,
                    Err((error, verified)) => {
                        core::mem::forget(verified);
                        return Err(BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)));
                    }
                };
                if let Err(error) = update.advance() {
                    core::mem::forget(update);
                    return Err(BootSystemRestoreError::Snapshot(snapshot_store_error_status(error)));
                }
                let (lease, token) = update.into_continuation()
                    .expect("paired WAL anchors published");
                publish_boot_wal_continuation(lease, token)?;
            }
            Some(BootSystemReserveOwner::Continuation { lease, token }) => {
                publish_boot_wal_continuation(lease, token)?;
            }
            Some(BootSystemReserveOwner::Legacy(lease)) => {
                core::mem::forget(lease);
                return Err(BootSystemRestoreError::MountBlocked);
            }
            None => return Err(BootSystemRestoreError::MountBlocked),
        }
        let fs = self.fs.as_ref().expect("unpublished boot filesystem");
        let nodes = fs.node_count();
        note_mounted_snapshot_format(self.format);
        let fs = self.fs.take().expect("verified boot filesystem");
        if install_writable_fs(fs, true).is_err() {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            return Err(BootSystemRestoreError::MountBlocked);
        }
        note_restored_snapshot(self.snapshot_generation, self.snapshot_bytes, nodes);
        Ok(())
    }
}

impl Drop for RestoredBootSystem {
    fn drop(&mut self) {
        if self.fs.is_some() {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BootSystemRestoreError {
    OverlayDisabled,
    MountBlocked,
    GeometryUnavailable,
    Snapshot(u32),
    Wal(nt_fs::RegistryWalError),
    WalSemantic(nt_hive_core::HiveLogReplayError),
    SystemStateMissing,
    PrimaryRead,
    LogRead,
}

fn owned_file_before_publish(
    fs: &nt_fs::FileSystem,
    path: &str,
    read_error: BootSystemRestoreError,
) -> Result<Option<alloc::vec::Vec<u8>>, BootSystemRestoreError> {
    fs.try_file_bytes_owned(path).map_err(|_| read_error)
}

fn verified_boot_log(
    metadata: nt_fs::StoredSnapshotMetadata,
    log: alloc::vec::Vec<u8>,
    lease: snapshot_storage::Lease,
    fs: &mut nt_fs::FileSystem,
) -> Result<(alloc::vec::Vec<u8>, Option<nt_hive_regf::BootSystemWalSuffix>, BootSystemReserveOwner), BootSystemRestoreError> {
    let nt_fs::SnapshotReadFormat::Wal { anchor, selected_base_serial } = metadata.format else {
        return Ok((log, None, BootSystemReserveOwner::Legacy(lease)));
    };
    let store = lease.store();
    let range = snapshot_storage::owned_wal_region(lease)
        .map_err(|(status, _lease)| BootSystemRestoreError::Snapshot(status))?;
    let mut wal = nt_fs::RegistryWal::recover(range, anchor.incarnation)
        .map_err(BootSystemRestoreError::Wal)?;
    if wal.state() == nt_fs::RegistryWalState::RecoveredUncommitted {
        if let Err(error) = wal.clear_recovered_tail() {
            // A failed clearing barrier owns an uncertain physical effect. Retain its exact
            // lease so no later mount or writer can reuse this reserve in the same boot.
            core::mem::forget(wal);
            return Err(BootSystemRestoreError::Wal(error));
        }
    }
    // The serial belongs to the physical volume, not to SYSTEM. Other hive journals can
    // interleave with legacy raw SYSTEM records, so the old SYSTEM-only concatenation would
    // feed their typed framing into CM. Authenticate the exact recovered prefix before routing
    // any record into the still-unpublished filesystem.
    let Some((incarnation, recovered_serial, _)) = wal.verified_prefix() else {
        return Err(BootSystemRestoreError::Snapshot(nt_fs::STATUS_DATA_ERROR));
    };
    if incarnation != anchor.incarnation
        || recovered_serial < anchor.serial
        || recovered_serial < selected_base_serial
        || wal.verified_record_end_lba(anchor.serial) != Some(anchor.end_lba)
    {
        return Err(BootSystemRestoreError::Snapshot(nt_fs::STATUS_DATA_ERROR));
    }
    let base = usize::try_from(selected_base_serial)
        .map_err(|_| BootSystemRestoreError::Snapshot(snapshot_store_error_status(nt_fs::SnapshotBlockStoreError::Corrupt)))?;
    let suffix = wal.records().get(base..)
        .ok_or(BootSystemRestoreError::Snapshot(snapshot_store_error_status(nt_fs::SnapshotBlockStoreError::Corrupt)))?;
    let snapshot_log_len = log.len();
    let mut verified_log = log;
    let mut first_sequence = None;
    let mut last_sequence = None;
    let mut hive_sequences: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for record in suffix {
        match nt_fs::decode_volume_wal_payload(&record.payload)
            .map_err(|_| BootSystemRestoreError::Snapshot(nt_fs::STATUS_DATA_ERROR))?
        {
            nt_fs::VolumeWalPayload::System(bytes) => {
                let span = if let Some(previous) = last_sequence {
                    nt_hive_core::complete_log_sequence_span_from(bytes, previous)
                } else {
                    nt_hive_core::complete_log_sequence_span(bytes)
                };
                let (first, last) = span.map_err(BootSystemRestoreError::WalSemantic)?;
                verified_log.try_reserve(bytes.len()).map_err(|_| {
                    BootSystemRestoreError::Snapshot(nt_fs::STATUS_INSUFFICIENT_RESOURCES)
                })?;
                verified_log.extend_from_slice(bytes);
                first_sequence.get_or_insert(first);
                last_sequence = Some(last);
            }
            nt_fs::VolumeWalPayload::HiveLog(payload) => {
                // The sector CRC covers the frame. Prove the contained hive record itself is
                // complete before appending it at its exact persisted file identity/offset.
                let previous = hive_sequences.iter_mut()
                    .find(|(file_id, _)| *file_id == payload.file_id);
                if let Some((_, previous_sequence)) = previous {
                    let span = nt_hive_core::complete_log_sequence_span_from(
                        payload.record, *previous_sequence,
                    ).map_err(BootSystemRestoreError::WalSemantic)?;
                    *previous_sequence = span.1;
                } else {
                    let last = hive_wal::validate_first_record(
                        fs, payload.path, payload.expected_log_len, payload.record,
                    )
                        .map_err(BootSystemRestoreError::Snapshot)?;
                    hive_sequences.try_reserve(1).map_err(|_| {
                        BootSystemRestoreError::Snapshot(nt_fs::STATUS_INSUFFICIENT_RESOURCES)
                    })?;
                    hive_sequences.push((payload.file_id, last));
                }
                fs.replay_hive_log_wal_payload(payload)
                    .map_err(|error| BootSystemRestoreError::Snapshot(match error {
                        nt_fs::HiveLogWalReplayError::OutOfMemory =>
                            nt_fs::STATUS_INSUFFICIENT_RESOURCES,
                        _ => nt_fs::STATUS_DATA_ERROR,
                    }))?;
                fs.protect_wal_log(payload.path, payload.file_id)
                    .map_err(BootSystemRestoreError::Snapshot)?;
            }
        }
    }
    let wal_suffix = first_sequence.zip(last_sequence).map(|(first_sequence, last_sequence)| {
        nt_hive_regf::BootSystemWalSuffix {
            snapshot_log_len,
            first_sequence,
            last_sequence,
        }
    });
    let verified = match wal.into_verified_device() {
        Ok(verified) => verified.into_full_device(),
        Err(wal) => {
            core::mem::forget(wal);
            return Err(BootSystemRestoreError::Wal(nt_fs::RegistryWalError::InvalidState));
        }
    };
    Ok((verified_log, wal_suffix, BootSystemReserveOwner::Wal { store, verified }))
}

/// Restore and classify persisted SYSTEM state before publishing or provisioning the writable FS.
///
/// `Absent` means the snapshot reserve was readable and both slots were genuinely empty. A restored
/// volume must contain a SYSTEM primary or non-empty SYSTEM journal. All other states fail closed.
///
/// # Safety
/// Single-threaded early boot, after the executable FAT volume is mounted and before hosted code.
pub(crate) unsafe fn restore_boot_system_persistence(
) -> Result<BootSystemPersistence, BootSystemRestoreError> {
    if registry_journal::owns_volume() {
        return Err(BootSystemRestoreError::Snapshot(snapshot_storage::BUSY));
    }
    if !WRITABLE_OVERLAY_MOUNTED {
        return Err(BootSystemRestoreError::OverlayDisabled);
    }
    if WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(BootSystemRestoreError::MountBlocked);
    }
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_some() {
        return Err(BootSystemRestoreError::MountBlocked);
    }
    if !snapshot_reserve_available() {
        return Err(BootSystemRestoreError::GeometryUnavailable);
    }
    let result = (|| match restore_boot_snapshot_volume_once() {
        Ok(Some((mut fs, metadata, lease))) => {
            let primary = owned_file_before_publish(
                &fs,
                CONFIG_SYSTEM_HIVE_PATH,
                BootSystemRestoreError::PrimaryRead,
            )?;
            let log_path = alloc::format!("{}.LOG", CONFIG_SYSTEM_HIVE_PATH);
            let snapshot_log = owned_file_before_publish(&fs, &log_path, BootSystemRestoreError::LogRead)?
                .unwrap_or_default();
            let (log, wal_suffix, lease) = verified_boot_log(metadata, snapshot_log, lease, &mut fs)?;
            SYSTEM_WAL_FOLD_REQUIRED.store(wal_suffix.is_some(), Ordering::Release);
            if primary.is_none() && log.is_empty() {
                return Err(BootSystemRestoreError::SystemStateMissing);
            }
            Ok(BootSystemPersistence::Restored(RestoredBootSystem {
                snapshot_generation: metadata.generation,
                snapshot_bytes: metadata.payload_len,
                primary,
                log,
                wal_suffix,
                fs: Some(fs),
                format: metadata.format,
                _lease: Some(lease),
            }))
        }
        Ok(None) => Ok(BootSystemPersistence::Absent),
        Err(snapshot_storage::BUSY) => Err(BootSystemRestoreError::Snapshot(snapshot_storage::BUSY)),
        Err(status) => {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            print_str(b"[writable-fs-snapshot] refusing writable mount after restore status=0x");
            print_hex(status);
            print_str(b"\n");
            Err(BootSystemRestoreError::Snapshot(status))
        }
    })();
    // Once a present snapshot was consumed, failure to inspect or install it must never permit
    // a later fresh-volume mount. Only admission contention is retryable without poisoning mount.
    if result.is_err()
        && !matches!(result, Err(BootSystemRestoreError::Snapshot(snapshot_storage::BUSY)))
    {
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    }
    result
}

/// Whether the volume has been mounted (i.e. something actually resolved into it).
pub(crate) unsafe fn writable_fs_mounted() -> bool {
    registry_journal::owns_volume() || (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_some()
}

/// Copy a complete internal file into caller-owned storage without exposing a filesystem borrow.
pub(crate) unsafe fn read_file_relative_into(
    relative: &[u8],
    output: &mut [u8],
) -> Result<Option<usize>, u32> {
    writable_fs()?.try_read_file_relative_into(relative, output)
}

/// Copy a mounted writable-volume file's full contents. This is for append-heavy internal files
/// such as hive sidecar logs, which can be extent-backed instead of one contiguous slice.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the copy.
pub(crate) unsafe fn file_bytes_owned_if_mounted(
    path: &str,
) -> Result<Option<alloc::vec::Vec<u8>>, u32> {
    let fs = mounted_namespace_fs()?.ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    fs.try_file_bytes_owned(path)
}

/// Inspect internal file metadata without treating unavailable storage as a missing file.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the query.
pub(crate) unsafe fn file_len_if_mounted(path: &str) -> Result<Option<usize>, u32> {
    let fs = mounted_namespace_fs()?.ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    fs.try_file_len(path)?
        .map(|len| usize::try_from(len).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES))
        .transpose()
}

/// Copy a mounted boot-hive journal sidecar, including extent-backed append files.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the copy.
pub(crate) unsafe fn hive_log_bytes_owned_if_mounted(
    image_path: &str,
) -> Result<Option<alloc::vec::Vec<u8>>, u32> {
    let log_path = alloc::format!("{}.LOG", image_path);
    file_bytes_owned_if_mounted(&log_path)
}

/// Return the mounted hive sidecar-log length without cloning the log into the bump heap.
///
/// # Safety
/// Single-threaded executive; callers must not mutate the writable volume while holding any
/// separately borrowed slices.
pub(crate) unsafe fn hive_log_len_if_mounted(image_path: &str) -> Result<usize, u32> {
    let log_path = alloc::format!("{}.LOG", image_path);
    Ok(file_len_if_mounted(&log_path)?.unwrap_or(0))
}

/// Consume the one-shot dirty bit set by the lazy writable-volume mount/materialisation.
pub(crate) fn take_mount_dirty() -> bool {
    WRITABLE_FS_MOUNT_DIRTY.swap(false, Ordering::AcqRel)
}

/// Consume the one-shot dirty bit set by durable mounted-volume runtime changes.
pub(crate) fn take_runtime_dirty() -> bool {
    WRITABLE_FS_RUNTIME_DIRTY.swap(false, Ordering::AcqRel)
}

pub(crate) fn writable_path_into(
    name: &[u16],
    folded: &mut [u8],
    relative: &mut [u8],
) -> Option<usize> {
    if !WRITABLE_OVERLAY_MOUNTED {
        return None;
    }
    nt_fs::writable_mount_relative_into(name, crate::installed_layout::ROOT, WRITABLE_PREFIXES, folded, relative)
}

/// Classify an NT object name into the local fixed C: volume without allocating. Unlike
/// [`writable_path_into`], this does not claim prefix ownership; callers use it for the writable
/// layer while an absent entry remains visible through the installed read-only FAT source.
pub(crate) fn volume_path_into(
    name: &[u16],
    folded: &mut [u8],
    relative: &mut [u8],
) -> Option<usize> {
    if !WRITABLE_OVERLAY_MOUNTED {
        return None;
    }
    nt_fs::nt_path_to_volume_relative_into(name, crate::installed_layout::ROOT, folded, relative)
}

/// `NtCreateFile` / `NtOpenFile` against the writable volume. Returns
/// `(status, Some(volume file-object id), information)`.
pub(crate) unsafe fn create(
    relative: &[u8],
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    disposition: u32,
    options: u32,
) -> (u32, Option<u64>, u64) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, None, 0),
    };
    let result = fs.zw_create_file_relative(
        relative,
        desired_access,
        file_attributes,
        share_access,
        disposition,
        options,
    );
    if result.status == nt_fs::STATUS_SUCCESS {
        mark_runtime_dirty();
        if create_information_changes_volume(result.information) {
            mark_snapshot_dirty();
        }
        match result.information {
            nt_fs::FILE_CREATED => {
                OVERLAY_CREATES.fetch_add(1, Ordering::Relaxed);
                if options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                    OVERLAY_DIRS_CREATED.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {
                OVERLAY_OPENS.fetch_add(1, Ordering::Relaxed);
            }
        }
        (
            result.status,
            Some(result.handle),
            result.information as u64,
        )
    } else {
        (result.status, None, 0)
    }
}

/// `NtCreateFile` / `NtOpenFile` beneath an existing writable-volume directory FILE_OBJECT.
/// Resolution starts from the filesystem's parent node identity; no absolute path is synthesized.
pub(crate) unsafe fn create_relative_to_directory(
    root_file_id: u64,
    relative: &[u8],
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    disposition: u32,
    options: u32,
) -> (u32, Option<u64>, u64) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, None, 0),
    };
    let result = fs.zw_create_file_relative_to_directory(
        root_file_id,
        relative,
        desired_access,
        file_attributes,
        share_access,
        disposition,
        options,
    );
    if result.status != nt_fs::STATUS_SUCCESS {
        return (result.status, None, 0);
    }
    mark_runtime_dirty();
    if create_information_changes_volume(result.information) {
        mark_snapshot_dirty();
    }
    match result.information {
        nt_fs::FILE_CREATED => {
            OVERLAY_CREATES.fetch_add(1, Ordering::Relaxed);
            if options & nt_fs::FILE_DIRECTORY_FILE != 0 {
                OVERLAY_DIRS_CREATED.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {
            OVERLAY_OPENS.fetch_add(1, Ordering::Relaxed);
        }
    }
    (
        result.status,
        Some(result.handle),
        result.information as u64,
    )
}

pub(crate) unsafe fn query_metadata_relative(
    relative: &[u8],
) -> Result<Option<nt_fs::FileMetadata>, u32> {
    OVERLAY_ATTR_QUERIES.fetch_add(1, Ordering::Relaxed);
    let fs = writable_fs()?;
    let info = fs.try_query_metadata_relative(relative)?;
    if info.is_some() {
        OVERLAY_ATTR_HITS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(info)
}

pub(crate) unsafe fn directory_entries_relative(
    relative: &[u8],
) -> Result<Option<alloc::vec::Vec<nt_fs::DirectoryEntry>>, u32> {
    writable_fs()?.try_directory_entries_relative(relative)
}

pub(crate) unsafe fn directory_entries_relative_if_mounted(
    relative: &[u8],
) -> Result<Option<alloc::vec::Vec<nt_fs::DirectoryEntry>>, u32> {
    match mounted_namespace_fs()? {
        Some(fs) => fs.try_directory_entries_relative(relative),
        None => Ok(None),
    }
}

pub(crate) unsafe fn directory_entries_opened_if_mounted(
    file_id: u64,
) -> Result<alloc::vec::Vec<nt_fs::DirectoryEntry>, u32> {
    mounted_namespace_fs()?.ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?
        .try_directory_entries_opened(file_id)
}

pub(crate) unsafe fn directory_entries_opened(
    file_id: u64,
) -> Result<alloc::vec::Vec<nt_fs::DirectoryEntry>, u32> {
    writable_fs()?.try_directory_entries_opened(file_id)
}

pub(crate) unsafe fn query_metadata_relative_to_directory(
    root_file_id: u64,
    relative: &[u8],
) -> Result<nt_fs::FileMetadata, u32> {
    let fs = writable_fs()?;
    fs.query_metadata_relative_to_directory(root_file_id, relative)
}

/// Query an existing writable-layer entry without mounting the writable volume. This is used by
/// fixed-drive union paths: an existing writable entry wins, but a missing writable entry must leave
/// the installed read-only FAT namespace visible.
pub(crate) unsafe fn query_metadata_relative_if_mounted(
    relative: &[u8],
) -> Result<Option<nt_fs::FileMetadata>, u32> {
    let Some(fs) = mounted_namespace_fs()? else {
        return Ok(None);
    };
    OVERLAY_ATTR_QUERIES.fetch_add(1, Ordering::Relaxed);
    let info = fs.try_query_metadata_relative(relative)?;
    if info.is_some() {
        OVERLAY_ATTR_HITS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(info)
}

/// Open an existing writable-layer entry without mounting the writable volume. Missing entries are
/// reported as `None` so the caller can continue resolving against the installed read-only source.
pub(crate) unsafe fn open_existing_relative_if_mounted(
    relative: &[u8],
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    options: u32,
) -> (u32, Option<u64>, u64) {
    let fs = match mounted_namespace_fs() {
        Ok(Some(fs)) => fs,
        Ok(None) => return (nt_fs::STATUS_OBJECT_NAME_NOT_FOUND, None, 0),
        Err(status) => return (status, None, 0),
    };
    let result = fs.zw_create_file_relative(
        relative,
        desired_access,
        file_attributes,
        share_access,
        nt_fs::FILE_OPEN,
        options,
    );
    if result.status == nt_fs::STATUS_SUCCESS {
        mark_runtime_dirty();
        OVERLAY_OPENS.fetch_add(1, Ordering::Relaxed);
        (
            result.status,
            Some(result.handle),
            result.information as u64,
        )
    } else {
        (result.status, None, 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstalledFileCopyUp {
    PreserveContents,
    MetadataOnly,
}

/// Import one installed FAT file into the writable volume before the caller's normal create/open.
/// The import publishes no process handle or File object. An existing writable entry wins without
/// modification, and a failed source read or filesystem import is returned to the caller rather
/// than converted into a successful empty file.
pub(crate) unsafe fn copy_up_installed_file(
    relative: &[u8],
    source: crate::fs_loader::FatOpenMetadata,
    mode: InstalledFileCopyUp,
) -> Result<bool, u32> {
    copy_up_installed_file_with_source(None, relative, source, mode)
}

pub(crate) unsafe fn copy_up_installed_file_from(
    fat: &crate::Fat32,
    relative: &[u8],
    source: crate::fs_loader::FatOpenMetadata,
    mode: InstalledFileCopyUp,
) -> Result<bool, u32> {
    copy_up_installed_file_with_source(Some(fat), relative, source, mode)
}

unsafe fn copy_up_installed_file_with_source(
    fat: Option<&crate::Fat32>,
    relative: &[u8],
    source: crate::fs_loader::FatOpenMetadata,
    mode: InstalledFileCopyUp,
) -> Result<bool, u32> {
    if source.metadata.is_directory {
        return Err(nt_fs::STATUS_FILE_IS_A_DIRECTORY);
    }
    let mut metadata = source.metadata;
    let bytes = match mode {
        InstalledFileCopyUp::PreserveContents => {
            let size = u32::try_from(metadata.end_of_file)
                .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
            let local;
            let fat = match fat {
                Some(fat) => fat,
                None => {
                    local = exec_fs().ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
                    &local
                }
            };
            read_staged_file_result(fat, source.first_cluster, size)?
        }
        InstalledFileCopyUp::MetadataOnly => {
            metadata.allocation_size = 0;
            metadata.end_of_file = 0;
            metadata.valid_data_length = 0;
            alloc::vec::Vec::new()
        }
    };
    let fs = writable_fs()?;
    let imported = fs.import_file_relative(relative, metadata, bytes)?;
    if imported {
        mark_runtime_dirty();
        mark_snapshot_dirty();
    }
    Ok(imported)
}

/// Materialize a directory whose existence was proved by the installed volume. Admission errors
/// must reach callers before they attempt to publish a copied-up child.
pub(crate) unsafe fn ensure_installed_directory_relative(relative: &[u8]) -> Result<bool, u32> {
    let fs = writable_fs()?;
    let before = fs.node_count();
    if !fs.provision_directory_relative(relative) {
        return Err(nt_fs::STATUS_OBJECT_PATH_NOT_FOUND);
    }
    let changed = fs.node_count() != before;
    if changed {
        mark_snapshot_dirty();
    }
    Ok(changed)
}

/// `NtReadFile` on a writable-volume file object.
pub(crate) unsafe fn read(
    file_id: u64,
    byte_offset: Option<u64>,
    length: usize,
) -> (u32, alloc::vec::Vec<u8>) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, alloc::vec::Vec::new()),
    };
    let (status, bytes) = fs.zw_read_file(file_id, byte_offset, length);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_READS.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_READ.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    } else {
        trace_io_refusal(b"read", file_id, byte_offset, length, status);
    }
    (status, bytes)
}

/// Raw backing fragments, without logical position, access metadata, or read accounting.
pub(crate) unsafe fn read_backing_into(
    file_id: u64,
    offset: u64,
    output: &mut [u8],
) -> (u32, usize) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, 0),
    };
    fs.read_backing_into(file_id, offset, output)
}

/// Transfer and account for one logical read before releasing writable-volume admission.
/// User copy and completion surfaces must follow this operation, never split its filesystem borrow.
pub(crate) unsafe fn read_completed_into(
    file_id: u64,
    resolved: nt_io_manager::ResolvedFileOffset,
    synchronous: bool,
    output: &mut [u8],
) -> (u32, usize) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, 0),
    };
    if let Err(status) = fs.query_file_object_information(file_id) {
        return (status, 0);
    }
    let (status, transferred) = fs.read_backing_into(file_id, resolved.value(), output);
    let position = resolved
        .completion_position(synchronous, output.len(), status, transferred)
        .expect("regular file read reports bounded progress");
    if status == nt_fs::STATUS_SUCCESS || transferred != 0 || position.is_some() {
        assert_eq!(
            fs.complete_read(file_id, transferred, position),
            nt_fs::STATUS_SUCCESS
        );
    }
    if status == nt_fs::STATUS_SUCCESS || transferred != 0 {
        OVERLAY_READS.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_READ.fetch_add(transferred as u64, Ordering::Relaxed);
    }
    if transferred != 0 {
        mark_snapshot_dirty();
    }
    if status != nt_fs::STATUS_SUCCESS {
        trace_io_refusal(b"read", file_id, Some(resolved.value()), output.len(), status);
    }
    (status, transferred)
}

/// Transfer and publish the I/O Manager's completed position under the same admission.
pub(crate) unsafe fn write_completed(
    file_id: u64,
    resolved: nt_io_manager::ResolvedFileOffset,
    synchronous: bool,
    data: &[u8],
) -> (u32, usize) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, 0),
    };
    if let Err(status) = fs.query_file_object_information(file_id) {
        return (status, 0);
    }
    let (status, written) = fs.zw_write_file(file_id, Some(resolved.value()), data);
    let position = resolved
        .completion_position(synchronous, data.len(), status, written)
        .expect("regular file write reports bounded progress");
    assert_eq!(
        fs.complete_file_position(file_id, position),
        nt_fs::STATUS_SUCCESS
    );
    account_write(file_id, Some(resolved.value()), data.len(), status, written);
    (status, written)
}

/// `NtReadFile` on a writable-volume file object into caller-owned staging.
pub(crate) unsafe fn read_into(
    file_id: u64,
    byte_offset: Option<u64>,
    output: &mut [u8],
) -> (u32, usize) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, 0),
    };
    let (status, read) = fs.zw_read_file_into(file_id, byte_offset, output);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_READS.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_READ.fetch_add(read as u64, Ordering::Relaxed);
    } else {
        trace_io_refusal(b"read", file_id, byte_offset, output.len(), status);
    }
    (status, read)
}

/// `NtWriteFile` on a writable-volume file object.
pub(crate) unsafe fn write(file_id: u64, byte_offset: Option<u64>, data: &[u8]) -> (u32, usize) {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return (status, 0),
    };
    let (status, written) = fs.zw_write_file(file_id, byte_offset, data);
    account_write(file_id, byte_offset, data.len(), status, written);
    (status, written)
}

fn account_write(
    file_id: u64,
    byte_offset: Option<u64>,
    requested: usize,
    status: u32,
    written: usize,
) {
    if status == nt_fs::STATUS_SUCCESS || written != 0 {
        OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_WRITTEN.fetch_add(written as u64, Ordering::Relaxed);
        if written != 0 {
            mark_snapshot_dirty();
        }
    }
    if status != nt_fs::STATUS_SUCCESS {
        trace_io_refusal(b"write", file_id, byte_offset, requested, status);
    }
}

/// Append bytes to a writable-volume file through the same Zw facade hosted callers use.
///
/// This is used by the hive journal sidecar. It avoids rebuilding the complete `.LOG` file for
/// every registry mutation, while still making the append an ordinary writable-volume update that
/// participates in snapshot persistence.
pub(crate) unsafe fn append_file(path: &str, data: &[u8]) -> u32 {
    if data.is_empty() {
        return nt_fs::STATUS_SUCCESS;
    }
    let status = 'append: {
        let fs = match writable_fs() {
            Ok(fs) => fs,
            Err(status) => break 'append status,
        };
        let (write_status, written) = fs.append_file_by_path(path, data);
        if write_status == nt_fs::STATUS_SUCCESS && written != data.len() {
            break 'append nt_fs::STATUS_INSUFFICIENT_RESOURCES;
        }
        write_status
    };
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_WRITTEN.fetch_add(data.len() as u64, Ordering::Relaxed);
        mark_snapshot_dirty();
    }
    status
}

/// Truncate a writable-volume file to zero bytes without replacing its node.
pub(crate) unsafe fn truncate_file(path: &str) -> u32 {
    truncate_file_to(path, 0)
}

/// Set a writable-volume file's durable length without replacing its node.
///
/// The SYSTEM hive write-ahead path records the previous sidecar length before append and uses this
/// only to roll back a failed CM publication.
pub(crate) unsafe fn truncate_file_to(path: &str, length: u64) -> u32 {
    let mut dirtied = false;
    let status = 'truncate: {
        let fs = match writable_fs() {
            Ok(fs) => fs,
            Err(status) => break 'truncate status,
        };
        let file = fs.zw_create_file(
            path,
            nt_fs::FILE_WRITE_DATA | nt_fs::SYNCHRONIZE,
            0,
            0,
            nt_fs::FILE_OPEN_IF,
            nt_fs::FILE_NON_DIRECTORY_FILE,
        );
        if file.status != nt_fs::STATUS_SUCCESS {
            break 'truncate file.status;
        }
        mark_runtime_dirty();
        let old_len = fs
            .zw_query_standard_information(file.handle)
            .map_or(0, |info| info.end_of_file);
        let eof = length.to_le_bytes();
        let set_status =
            fs.zw_set_information_file(file.handle, nt_fs::FILE_END_OF_FILE_INFORMATION, &eof);
        let flush_status = if set_status == nt_fs::STATUS_SUCCESS {
            fs.zw_flush_buffers_file(file.handle)
        } else {
            set_status
        };
        dirtied = old_len != length || file.information == nt_fs::FILE_CREATED;
        let _ = fs.zw_close(file.handle);
        flush_status
    };
    if status == nt_fs::STATUS_SUCCESS && dirtied {
        OVERLAY_SET_INFO.fetch_add(1, Ordering::Relaxed);
        mark_snapshot_dirty();
    }
    status
}

fn rename_information(
    replace_if_exists: bool,
    root_directory: u64,
    target_path: &str,
) -> Result<alloc::vec::Vec<u8>, u32> {
    let name_len = target_path
        .encode_utf16()
        .count()
        .checked_mul(2)
        .ok_or(nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    let name_len_u32 = u32::try_from(name_len).map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    let total_len = 20usize
        .checked_add(name_len)
        .ok_or(nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    let mut info = alloc::vec::Vec::new();
    info.try_reserve_exact(total_len)
        .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    info.resize(20, 0);
    info[0] = u8::from(replace_if_exists);
    info[8..16].copy_from_slice(&root_directory.to_le_bytes());
    info[16..20].copy_from_slice(&name_len_u32.to_le_bytes());
    for unit in target_path.encode_utf16() {
        info.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(info)
}

fn delete_open_file(fs: &mut nt_fs::FileSystem, handle: u64) {
    let _ = fs.zw_set_information_file(handle, nt_fs::FILE_DISPOSITION_INFORMATION, &[1]);
    let _ = fs.zw_close(handle);
}

/// Atomically replace a writable-volume file with an already-owned byte image using the same
/// temp-file + `FileRenameInformation` contract as the hive I/O provider.
///
/// # Safety
/// Single-threaded executive; borrows the mounted writable volume for the duration of the replace.
pub(crate) unsafe fn write_file_atomic_owned(path: &str, bytes: alloc::vec::Vec<u8>) -> u32 {
    let byte_len = bytes.len();
    let status = 'replace: {
        let fs = match writable_fs() {
            Ok(fs) => fs,
            Err(status) => break 'replace status,
        };
        let tmp_path = alloc::format!("{}.TMP", path);
        let create = fs.zw_create_file(
            &tmp_path,
            nt_fs::FILE_WRITE_DATA | nt_fs::SYNCHRONIZE,
            0,
            0,
            nt_fs::FILE_OVERWRITE_IF,
            0,
        );
        if create.status != nt_fs::STATUS_SUCCESS {
            break 'replace create.status;
        }
        mark_runtime_dirty();

        let write_status = fs.replace_file_data_owned(create.handle, bytes);
        if write_status != nt_fs::STATUS_SUCCESS {
            delete_open_file(fs, create.handle);
            break 'replace write_status;
        }

        let eof = (byte_len as u64).to_le_bytes();
        let status =
            fs.zw_set_information_file(create.handle, nt_fs::FILE_END_OF_FILE_INFORMATION, &eof);
        if status != nt_fs::STATUS_SUCCESS {
            delete_open_file(fs, create.handle);
            break 'replace status;
        }
        let status = fs.zw_flush_buffers_file(create.handle);
        if status != nt_fs::STATUS_SUCCESS {
            delete_open_file(fs, create.handle);
            break 'replace status;
        }

        let rename = match rename_information(true, 0, path) {
            Ok(rename) => rename,
            Err(status) => {
                delete_open_file(fs, create.handle);
                break 'replace status;
            }
        };
        let status =
            fs.zw_set_information_file(create.handle, nt_fs::FILE_RENAME_INFORMATION, &rename);
        if status != nt_fs::STATUS_SUCCESS {
            delete_open_file(fs, create.handle);
            break 'replace status;
        }
        let status = fs.zw_flush_buffers_file(create.handle);
        let _ = fs.zw_close(create.handle);
        status
    };
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_WRITTEN.fetch_add(byte_len as u64, Ordering::Relaxed);
        OVERLAY_SET_INFO.fetch_add(1, Ordering::Relaxed);
        mark_snapshot_dirty();
    }
    status
}

fn hive_io_status(status: u32) -> Result<(), nt_hive_core::HiveIoError> {
    if status == nt_fs::STATUS_SUCCESS {
        Ok(())
    } else {
        Err(nt_hive_core::HiveIoError::Io)
    }
}

/// Writable-volume backing for `nt-hive-core`'s image + log provider contract.
///
/// Images and logs are ordinary files in the same writable namespace hosted processes use. The log
/// path is a sidecar (`<image>.LOG`) so a later checkpoint can atomically replace the primary image
/// and truncate the replay tail without inventing another executive-local persistence plane.
pub(crate) struct WritableHiveIoProvider {
    image_path: alloc::string::String,
    log_path: alloc::string::String,
}

impl WritableHiveIoProvider {
    pub(crate) fn new(image_path: &str) -> Self {
        Self {
            image_path: alloc::string::String::from(image_path),
            log_path: alloc::format!("{}.LOG", image_path),
        }
    }

    fn require_pre_native_mutation(&self) -> Result<(), nt_hive_core::HiveIoError> {
        match unsafe { crate::fs_loader::exec_fs_mount_identity() }
            .and_then(crate::fs_loader::exec_block_route_kind)
        {
            Some(nt_fs::BlockSourceKind::Native | nt_fs::BlockSourceKind::Draining) =>
                Err(nt_hive_core::HiveIoError::NotSupported),
            _ => Ok(()),
        }
    }

    pub(crate) fn log_len(&self) -> Result<usize, nt_hive_core::HiveIoError> {
        unsafe { hive_log_len_if_mounted(&self.image_path) }
            .map_err(|_| nt_hive_core::HiveIoError::Io)
    }

    fn require_legacy_file_mutation(&self) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_pre_native_mutation()?;
        // The format bit is set by mount. Checking it before a lazy mount would mistake
        // a restored v2 volume for an empty legacy volume. Every v2 hive mutation enters
        // through the retained native journal owner, including a boot-phase caller.
        unsafe { ensure_mounted() }.map_err(|_| nt_hive_core::HiveIoError::Io)?;
        if legacy_snapshot_writes_allowed() {
            Ok(())
        } else {
            Err(nt_hive_core::HiveIoError::NotSupported)
        }
    }

    pub(crate) fn truncate_log_to(
        &mut self,
        length: usize,
    ) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_legacy_file_mutation()?;
        let length = u64::try_from(length).map_err(|_| nt_hive_core::HiveIoError::Io)?;
        hive_io_status(unsafe { truncate_file_to(&self.log_path, length) })
    }
}

impl nt_hive_core::HiveIoProvider for WritableHiveIoProvider {
    fn provider_kind(&self) -> nt_hive_core::HiveIoProviderKind {
        nt_hive_core::HiveIoProviderKind::NtFile
    }

    fn read_primary_image(
        &mut self,
    ) -> Result<Option<alloc::vec::Vec<u8>>, nt_hive_core::HiveIoError> {
        unsafe { file_bytes_owned_if_mounted(&self.image_path) }
            .map_err(|_| nt_hive_core::HiveIoError::Io)
    }

    fn write_primary_image_atomic(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), nt_hive_core::HiveIoError> {
        self.write_primary_image_atomic_owned(bytes.to_vec())
    }

    fn write_primary_image_atomic_owned(
        &mut self,
        bytes: alloc::vec::Vec<u8>,
    ) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_legacy_file_mutation()?;
        hive_io_status(unsafe { write_file_atomic_owned(&self.image_path, bytes) })
    }

    fn read_log(&mut self) -> Result<alloc::vec::Vec<u8>, nt_hive_core::HiveIoError> {
        Ok(unsafe { file_bytes_owned_if_mounted(&self.log_path) }
            .map_err(|_| nt_hive_core::HiveIoError::Io)?
            .unwrap_or_default())
    }

    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_legacy_file_mutation()?;
        let _scope = crate::allocator::enter_scope(b"memfs.hive-journal-append");
        hive_io_status(unsafe { append_file(&self.log_path, bytes) })
    }

    fn truncate_log(&mut self) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_legacy_file_mutation()?;
        hive_io_status(unsafe { truncate_file(&self.log_path) })
    }

    fn flush_image(&mut self) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_pre_native_mutation()?;
        // Hive bytes live in the writable volume. A file-cache flush alone does not publish
        // its immutable snapshot or issue the backing device's durability barrier.
        unsafe { checkpoint_dirty_volume() }
            .map(|_| ())
            .map_err(|_| nt_hive_core::HiveIoError::Io)
    }

    fn flush_log(&mut self) -> Result<(), nt_hive_core::HiveIoError> {
        self.require_pre_native_mutation()?;
        unsafe { checkpoint_dirty_volume() }
            .map(|_| ())
            .map_err(|_| nt_hive_core::HiveIoError::Io)
    }

    fn get_status(&self) -> Result<nt_hive_core::HiveIoStatus, nt_hive_core::HiveIoError> {
        let image_present = unsafe { file_len_if_mounted(&self.image_path) }
            .map_err(|_| nt_hive_core::HiveIoError::Io)?
            .is_some();
        let log_len = self.log_len()?;
        Ok(nt_hive_core::HiveIoStatus {
            image_present,
            log_len,
        })
    }
}

/// `NtFlushBuffersFile` on a writable-volume file object.
pub(crate) unsafe fn flush(file_id: u64) -> u32 {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return status,
    };
    fs.zw_flush_buffers_file(file_id)
}

/// Capture file metadata, position and mode under the same writable-volume admission.
pub(crate) unsafe fn file_object_information(file_id: u64) -> Result<nt_fs::FileObjectInformation, u32> {
    writable_fs()?.query_file_object_information(file_id)
}

pub(crate) unsafe fn section_backing(
    file_id: u64,
) -> Result<nt_memory_manager::GenericSectionBacking, u32> {
    let info = file_object_information(file_id)?.metadata;
    let mount = (*core::ptr::addr_of!(WRITABLE_MOUNT_ID)).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    Ok(nt_memory_manager::GenericSectionBacking::overlay(
        file_id,
        nt_memory_manager::SectionFileIdentity {
            mount,
            file_id: info.file_id,
        },
        info.end_of_file,
    ))
}

pub(crate) unsafe fn opened_name(file_id: u64) -> Result<alloc::string::String, u32> {
    writable_fs()?.query_opened_name(file_id)
}

pub(crate) unsafe fn short_name(file_id: u64) -> Result<nt_fs::FileShortName, u32> {
    writable_fs()?.query_short_name(file_id)
}

/// `NtSetInformationFile` on a writable-volume file object.
pub(crate) unsafe fn set_information(file_id: u64, class: u32, data: &[u8]) -> u32 {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return status,
    };
    let status = fs.zw_set_information_file(file_id, class, data);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_SET_INFO.fetch_add(1, Ordering::Relaxed);
        mark_snapshot_dirty();
    }
    status
}

/// Capture create-time security context on the filesystem's open description before its process
/// handle is published. The filesystem retains this across handle duplication like an FSD CCB.
pub(crate) unsafe fn capture_open_privileges(
    file_id: u64,
    privileges: nt_fs::FileOpenPrivileges,
) -> u32 {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return status,
    };
    fs.capture_open_privileges(file_id, privileges)
}

/// Rename a writable-volume File using a canonical filesystem parse root.
/// Process handles are resolved by the executive before entering this boundary.
pub(crate) unsafe fn rename(
    file_id: u64,
    root: nt_fs::FileRenameRoot,
    target_name: &[u8],
    replace_if_exists: bool,
) -> u32 {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return status,
    };
    let status = fs.zw_rename_file(file_id, root, target_name, replace_if_exists);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_SET_INFO.fetch_add(1, Ordering::Relaxed);
        mark_snapshot_dirty();
    }
    status
}

/// Create a hard link to a writable-volume File through a canonical filesystem parse root.
/// Process handles are resolved by the executive before entering this boundary.
pub(crate) unsafe fn link(
    file_id: u64,
    root: nt_fs::FileRenameRoot,
    target_name: &[u8],
    replace_if_exists: bool,
) -> u32 {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => return status,
    };
    let status = fs.zw_link_file(file_id, root, target_name, replace_if_exists);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_SET_INFO.fetch_add(1, Ordering::Relaxed);
        mark_snapshot_dirty();
    }
    status
}

/// `NtQueryDirectoryFile` on a writable-volume DIRECTORY file object.
pub(crate) unsafe fn query_directory(
    file_id: u64,
    information_class: u32,
    return_single_entry: bool,
    pattern: Option<&[u16]>,
    restart_scan: bool,
    output: &mut [u8],
) -> nt_fs::DirectoryQueryResult {
    let fs = match writable_fs() {
        Ok(fs) => fs,
        Err(status) => {
            return nt_fs::DirectoryQueryResult { status, information: 0 };
        }
    };
    let result = fs.zw_query_directory_file(
        file_id,
        information_class,
        return_single_entry,
        pattern,
        restart_scan,
        output,
    );
    OVERLAY_DIR_QUERIES.fetch_add(1, Ordering::Relaxed);
    if result.status == nt_fs::STATUS_SUCCESS {
        OVERLAY_DIR_ENTRIES.fetch_add(1, Ordering::Relaxed);
    } else if DIR_QUERY_MISS_TRACED.fetch_add(1, Ordering::Relaxed) < 4 {
        print_str(b"[writable-fs] dir-query MISS status=0x");
        print_hex(result.status);
        print_str(b" class=");
        print_u64(information_class as u64);
        print_str(b" single=");
        print_u64(return_single_entry as u64);
        print_str(b" restart=");
        print_u64(restart_scan as u64);
        print_str(b" out-len=");
        print_u64(output.len() as u64);
        print_str(b" pattern=\"");
        for &unit in pattern.unwrap_or(&[]).iter().take(32) {
            debug_put_char(if (0x20..0x7f).contains(&unit) {
                unit as u8
            } else {
                b'?'
            });
        }
        print_str(b"\"\n");
    }
    result
}

static IO_REFUSAL_TRACED: AtomicU64 = AtomicU64::new(0);

/// Trace (bounded) a read/write the volume REFUSED. `CopyFileW`'s failures surface in userenv as a
/// bare `GetLastError()` number, so the NTSTATUS that produced it has to be visible here or the
/// frontier is a guess.
fn trace_io_refusal(what: &[u8], file_id: u64, offset: Option<u64>, length: usize, status: u32) {
    if IO_REFUSAL_TRACED.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    print_str(b"[writable-fs] ");
    print_str(what);
    print_str(b" REFUSED id=");
    print_u64(file_id);
    print_str(b" off=");
    print_u64(offset.unwrap_or(u64::MAX));
    print_str(b" len=");
    print_u64(length as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

static DIR_QUERY_MISS_TRACED: AtomicU64 = AtomicU64::new(0);
static DIR_REFUSAL_TRACED: AtomicU64 = AtomicU64::new(0);

/// Trace (a bounded number of times) an `NtQueryDirectoryFile` — its entry arguments, and any
/// refusal the executive made BEFORE the call reached a volume, with everything needed to tell the
/// refusals apart (they all map to the same `GetLastError()` values, so guessing is not an option).
pub(crate) fn trace_dir_refusal(
    why: &[u8],
    pi: usize,
    handle: u64,
    iosb: u64,
    output: u64,
    length: usize,
    class: u64,
) {
    if DIR_REFUSAL_TRACED.fetch_add(1, Ordering::Relaxed) >= 24 {
        return;
    }
    print_str(b"[query-dir] ");
    print_str(why);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" handle=0x");
    print_hex(handle as u32);
    print_str(b" iosb=0x");
    print_hex((iosb >> 32) as u32);
    print_hex(iosb as u32);
    print_str(b" out=0x");
    print_hex((output >> 32) as u32);
    print_hex(output as u32);
    print_str(b" len=");
    print_u64(length as u64);
    print_str(b" class=");
    print_u64(class);
    print_str(b"\n");
}

/// `NtDuplicateObject` on a writable-volume file object.
pub(crate) unsafe fn retain(file_id: u64) -> Result<(), u32> {
    let fs = writable_fs()?;
    match fs.zw_retain(file_id) {
        nt_fs::STATUS_SUCCESS => {
            mark_runtime_dirty();
            Ok(())
        }
        status => Err(status),
    }
}

pub(crate) unsafe fn is_final_reference(file_id: u64) -> Result<bool, u32> {
    writable_fs()?.zw_is_final_reference(file_id)
}

pub(crate) unsafe fn retain_io_reference(file_id: u64) -> Result<(), u32> {
    writable_fs()?.zw_retain_io_reference(file_id)
}

/// Retain the operation reference and clear the file signal as one checked transition.
pub(crate) unsafe fn begin_file_io(file_id: u64) -> Result<(), u32> {
    writable_fs()?.zw_begin_file_io(file_id)
}

pub(crate) unsafe fn begin_referenced_file_io(file_id: u64) -> Result<(), u32> {
    writable_fs()?.zw_begin_referenced_file_io(file_id)
}

pub(crate) unsafe fn release_io_reference(file_id: u64) -> Result<(), u32> {
    let fs = writable_fs()?;
    let result = fs.zw_release_io_reference(file_id);
    publish_file_cleanup_effects(fs);
    result
}

pub(crate) unsafe fn set_file_signaled(file_id: u64, signaled: bool) -> Result<(), u32> {
    writable_fs()?.zw_set_file_signaled(file_id, signaled)
}

pub(crate) unsafe fn is_file_signaled(file_id: u64) -> Result<bool, u32> {
    writable_fs()?.zw_is_file_signaled(file_id)
}

pub(crate) unsafe fn notify_change_directory(
    file_id: u64,
    completion_filter: u32,
    watch_tree: bool,
    buffer_length: u32,
    context: u64,
) -> Result<nt_fs::DirectoryNotifyId, u32> {
    writable_fs()?.zw_notify_change_directory_file(
        file_id,
        completion_filter,
        watch_tree,
        buffer_length,
        context,
    )
}

pub(crate) unsafe fn cancel_directory_notify(id: nt_fs::DirectoryNotifyId) -> Result<bool, u32> {
    Ok(writable_fs()?.zw_cancel_directory_notify(id))
}

pub(crate) unsafe fn directory_notify_completion(
    id: nt_fs::DirectoryNotifyId,
    context: u64,
) -> Result<Option<(u32, u32)>, u32> {
    Ok(writable_fs()?
        .directory_notify_completion_exact(id, context)?
        .map(|completion| (completion.status, completion.information)))
}

pub(crate) unsafe fn copy_directory_notify_completion(
    id: nt_fs::DirectoryNotifyId,
    context: u64,
    offset: usize,
    output: &mut [u8],
) -> Result<usize, u32> {
    writable_fs()?.copy_directory_notify_completion(id, context, offset, output)
}

pub(crate) unsafe fn acknowledge_directory_notify_completion(
    id: nt_fs::DirectoryNotifyId,
    context: u64,
) -> Result<(), u32> {
    writable_fs()?.acknowledge_directory_notify_completion(id, context)
}

/// `NtClose` on a writable-volume file object (honours a pending delete).
pub(crate) unsafe fn close(file_id: u64) {
    let _ = close_checked(file_id);
}

/// Preserve an unconsumed File handle if cleanup admission fails.
pub(crate) unsafe fn close_checked(file_id: u64) -> Result<(), u32> {
    let fs = writable_fs()?;
    let result = fs.zw_close(file_id);
    if result == nt_fs::STATUS_SUCCESS {
        OVERLAY_CLOSES.fetch_add(1, Ordering::Relaxed);
    }
    publish_file_cleanup_effects(fs);
    if result == nt_fs::STATUS_SUCCESS {
        Ok(())
    } else {
        Err(result)
    }
}

/// The genuine `\reactos\system32\config\default` bytes, borrowed from the live DEFHIVEBUF mapping
/// the isolated storage host filled BY PATH. `None` when the host did not report a size.
///
/// # Safety
/// DEFHIVEBUF is a fixed, executive-lifetime mapping; the reported size is bounded by its window.
pub(crate) unsafe fn default_hive_bytes() -> Option<&'static [u8]> {
    let size = DEFAULT_HIVE_SIZE.load(Ordering::Relaxed) as usize;
    if size == 0 || size > (DEFHIVEBUF_FRAMES * 0x1000) as usize {
        return None;
    }
    Some(core::slice::from_raw_parts(
        DEFHIVEBUF_VADDR as *const u8,
        size,
    ))
}

/// MATERIALISE the ISO's staged `\Profiles` tree onto the writable volume.
///
/// This is a real recursive copy off the READ-ONLY FAT volume — the same `fat_visit_directory` /
/// `dir_find_lfn` / `fat_read_file` reader every hosted binary is loaded with — into the writable
/// volume's ordinary create surface. Every directory and every file byte comes from the image;
/// nothing is invented. The result is then read back the way a hosted process reads it (by path,
/// by content and by ENUMERATION) so the "real, enumerable tree" claim is measured, not asserted.
///
/// Read a staged FAT file into temporary storage before handing it to the writable filesystem. The
/// filesystem copies the bytes into its own file record, so this buffer is released after each file
/// instead of becoming long-lived mounted state.
unsafe fn read_staged_file_result(
    fat: &Fat32,
    cluster: u32,
    size: u32,
) -> Result<alloc::vec::Vec<u8>, u32> {
    const STATUS_IO_DEVICE_ERROR: u32 = 0xC000_0185;

    let len = size as usize;
    let mut data = alloc::vec::Vec::new();
    data.try_reserve_exact(len)
        .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    data.resize(len, 0);
    let got = if size == 0 {
        0
    } else {
        crate::fs_loader::fat_read_file(fat, cluster, size, data.as_mut_ptr() as u64)
    };
    if got != size {
        return Err(STATUS_IO_DEVICE_ERROR);
    }
    Ok(data)
}

unsafe fn read_staged_file(fat: &Fat32, cluster: u32, size: u32) -> Option<alloc::vec::Vec<u8>> {
    read_staged_file_result(fat, cluster, size).ok()
}

#[derive(Clone, Copy, Default)]
struct StagedTreeStats {
    dirs: u64,
    files: u64,
    bytes: u64,
    skipped_large_files: u64,
    deferred_boot_hives: u64,
}

fn is_deferred_boot_hive_source(relative: &[u8]) -> bool {
    [
        CONFIG_SYSTEM_HIVE_RELATIVE,
        CONFIG_SOFTWARE_HIVE_RELATIVE,
        CONFIG_SECURITY_HIVE_RELATIVE,
        CONFIG_SAM_HIVE_RELATIVE,
        CONFIG_DEFAULT_HIVE_RELATIVE,
    ]
    .iter()
    .any(|candidate| relative.eq_ignore_ascii_case(candidate))
}

unsafe fn provision_staged_tree(
    fs: &mut nt_fs::FileSystem,
    fat: &Fat32,
    root_cluster: u32,
    volume_root_relative: &[u8],
    max_depth: u32,
) -> StagedTreeStats {
    // Explicit DFS stack (no recursion in the executive): (fat cluster, volume path of the dir).
    let mut stack: alloc::vec::Vec<(u32, alloc::vec::Vec<u8>, u32)> = alloc::vec::Vec::new();
    let _ = fs.provision_directory_relative(volume_root_relative);
    stack.push((root_cluster, volume_root_relative.to_vec(), 0));
    let mut stats = StagedTreeStats::default();
    while let Some((cluster, base, depth)) = stack.pop() {
        // Collect this directory's children first: `fat_visit_directory` and `dir_find_lfn` both
        // drive the sector cache, so the names are captured before any further reads.
        let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
        crate::fs_loader::fat_visit_directory(fat, cluster, |entry, _first_cluster| {
            let mut name = alloc::string::String::new();
            for &unit in entry.name() {
                if unit == 0 || unit > 0x7f {
                    return true; // non-ASCII name: skip it rather than mangle it
                }
                name.push(unit as u8 as char);
            }
            if !name.is_empty() && name != "." && name != ".." {
                names.push(name);
            }
            true
        });
        for name in names {
            let Some((child, size, child_attr)) =
                crate::fs_loader::dir_find_lfn(fat, cluster, name.as_bytes())
            else {
                continue;
            };
            let mut path = base.clone();
            path.push(b'\\');
            path.extend_from_slice(name.as_bytes());
            if child_attr & 0x10 != 0 {
                if fs.provision_directory_relative(&path) {
                    stats.dirs += 1;
                    if depth + 1 < max_depth {
                        stack.push((child, path, depth + 1));
                    }
                }
            } else if is_deferred_boot_hive_source(&path) {
                stats.deferred_boot_hives += 1;
            } else if let Some(data) = read_staged_file(fat, child, size) {
                if fs.provision_file_relative(&path, &data) {
                    stats.files += 1;
                    stats.bytes += size as u64;
                }
            } else {
                stats.skipped_large_files += 1;
            }
        }
    }
    stats
}

unsafe fn staged_config_hive_ok(fat: &Fat32, root_cluster: u32, leaf: &[u8]) -> bool {
    let Some((cluster, size, attr)) = crate::fs_loader::dir_find_lfn(fat, root_cluster, leaf)
    else {
        return false;
    };
    if attr & 0x10 != 0 {
        return false;
    }
    read_staged_file(fat, cluster, size)
        .as_deref()
        .is_some_and(hive_image_ok)
}

unsafe fn provision_staged_profiles(fs: &mut nt_fs::FileSystem) {
    let Some(fat) = crate::fs_loader::exec_fs() else {
        print_str(b"[profile-source] no FAT volume -> \\Profiles NOT materialised\n");
        return;
    };
    let Some((root_cluster, _, attr)) =
        crate::fs_loader::dir_find_lfn(&fat, fat.root_cl, STAGED_PROFILES_DIR)
    else {
        print_str(b"[profile-source] ::Profiles ABSENT from the image -> not materialised\n");
        return;
    };
    if attr & 0x10 == 0 {
        return;
    }
    let mut stats =
        provision_staged_tree(fs, &fat, root_cluster, PROFILES_VOLUME_ROOT_RELATIVE, 12);
    PROFILE_SOURCE_DIRS.store(stats.dirs, Ordering::Relaxed);
    PROFILE_SOURCE_FILES.store(stats.files, Ordering::Relaxed);
    PROFILE_SOURCE_BYTES.store(stats.bytes, Ordering::Relaxed);
    // Read a REAL staged file back off the live volume, by content.
    if fs
        .query_attributes(DEFAULT_USER_PROBE_FILE)
        .is_some_and(|info| info.is_directory)
    {
        PROFILE_SOURCE_PROBE_OK.store(1, Ordering::Relaxed);
    }
    // ★ THE SETUP STEP THE LIVECD SKIPS (see `PROVISION_NTUSER_DAT`): give the `Default User`
    // profile the `ntuser.dat` setup would have made for it from the setup-provisioned mutable
    // `.Default` checkpoint image. Do not copy raw `config\default`: that prototype lacks setup's
    // installed-user writes and is the bug this path replaces.
    if PROVISION_NTUSER_DAT {
        let setup_image = (*core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE)).take();
        match setup_image {
            Some(hive) if hive_image_ok(&hive) => {
                let hive_len = hive.len();
                match fs.provision_file_owned(DEFAULT_USER_NTUSER_DAT, hive) {
                    Ok(()) => {
                        stats.files += 1;
                        stats.bytes += hive_len as u64;
                        NTUSER_DAT_PROVISIONED.store(hive_len as u64, Ordering::Relaxed);
                    }
                    Err(returned) => {
                        *core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE) = Some(returned);
                    }
                }
            }
            Some(_) => {
                print_str(b"[profile-source] setup HKU\\.DEFAULT image invalid -> no ntuser.dat\n")
            }
            None => {
                print_str(b"[profile-source] setup HKU\\.DEFAULT image absent -> no ntuser.dat\n")
            }
        }
        PROFILE_SOURCE_DIRS.store(stats.dirs, Ordering::Relaxed);
        PROFILE_SOURCE_FILES.store(stats.files, Ordering::Relaxed);
        PROFILE_SOURCE_BYTES.store(stats.bytes, Ordering::Relaxed);
    }
    PROFILE_SOURCE_ENTRIES.store(
        count_entries(fs, DEFAULT_USER_PROFILE_DIR),
        Ordering::Relaxed,
    );
    print_str(b"[profile-source] materialised ::Profiles onto the writable volume: dirs=");
    print_u64(stats.dirs);
    print_str(b" files=");
    print_u64(stats.files);
    print_str(b" bytes=");
    print_u64(stats.bytes);
    print_str(b" `Default User` dir-entries=");
    print_u64(PROFILE_SOURCE_ENTRIES.load(Ordering::Relaxed));
    print_str(b" probe-file-content-ok=");
    print_u64(PROFILE_SOURCE_PROBE_OK.load(Ordering::Relaxed));
    print_str(b" ntuser.dat=");
    print_u64(NTUSER_DAT_PROVISIONED.load(Ordering::Relaxed));
    print_str(b"B(hive-ok=");
    // Read it back off the LIVE volume and parse it, so the claim "a real hive image is in the
    // source profile" is measured through the same navigator the registry will mount it with.
    print_u64(hive_image_len_on(fs, DEFAULT_USER_NTUSER_DAT) as u64);
    print_str(b")\n");
}

unsafe fn provision_staged_config(fs: &mut nt_fs::FileSystem) {
    let Some(fat) = crate::fs_loader::exec_fs() else {
        print_str(b"[config-source] no FAT volume -> system32\\config NOT materialised\n");
        return;
    };
    let Some((root_cluster, _, attr)) =
        crate::fs_loader::fat_open_path_entry(&fat, STAGED_CONFIG_DIR)
    else {
        print_str(b"[config-source] reactos\\system32\\config ABSENT -> not materialised\n");
        return;
    };
    if attr & 0x10 == 0 {
        return;
    }
    let stats = provision_staged_tree(fs, &fat, root_cluster, CONFIG_VOLUME_ROOT_RELATIVE, 4);
    CONFIG_SOURCE_DIRS.store(stats.dirs, Ordering::Relaxed);
    CONFIG_SOURCE_FILES.store(stats.files, Ordering::Relaxed);
    CONFIG_SOURCE_BYTES.store(stats.bytes, Ordering::Relaxed);
    let system_hive_ok = staged_config_hive_ok(&fat, root_cluster, b"system");
    let software_hive_ok = staged_config_hive_ok(&fat, root_cluster, b"software");
    CONFIG_SOURCE_SYSTEM_HIVE_OK.store(system_hive_ok as u64, Ordering::Relaxed);
    CONFIG_SOURCE_SOFTWARE_HIVE_OK.store(software_hive_ok as u64, Ordering::Relaxed);
    print_str(
        b"[config-source] materialised reactos\\system32\\config onto the writable volume: dirs=",
    );
    print_u64(stats.dirs);
    print_str(b" files=");
    print_u64(stats.files);
    print_str(b" bytes=");
    print_u64(stats.bytes);
    print_str(b" skipped-large=");
    print_u64(stats.skipped_large_files);
    print_str(b" deferred-boot-hives=");
    print_u64(stats.deferred_boot_hives);
    print_str(b" system-hive-ok=");
    print_u64(system_hive_ok as u64);
    print_str(b" software-hive-ok=");
    print_u64(software_hive_ok as u64);
    print_str(b"\n");
}

/// How many records a directory really enumerates through the `Zw*` surface (`.`, `..`, children) —
/// the same encoder `NtQueryDirectoryFile`, and therefore `FindFirstFileW`, goes through.
fn count_entries(fs: &mut nt_fs::FileSystem, path: &str) -> u64 {
    let dir = fs.zw_create_file(
        path,
        nt_fs::FILE_READ_DATA,
        0,
        0,
        nt_fs::FILE_OPEN,
        nt_fs::FILE_DIRECTORY_FILE,
    );
    if dir.status != nt_fs::STATUS_SUCCESS {
        return 0;
    }
    let mut buffer = [0u8; 4096];
    let result = fs.zw_query_directory_file(
        dir.handle,
        nt_fs::FILE_DIRECTORY_INFORMATION,
        false,
        None,
        true,
        &mut buffer,
    );
    let mut names = 0u64;
    if result.status == nt_fs::STATUS_SUCCESS {
        let mut offset = 0usize;
        loop {
            if offset + 64 > result.information {
                break;
            }
            names += 1;
            let next = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
    fs.zw_close(dir.handle);
    names
}

/// Mount-time PROOF that this is a real filesystem, exercised through the same `Zw*` surface the
/// hosted processes use: create a directory, create a file in it, write bytes, read them back,
/// enumerate the directory and see the file, then delete both and confirm they are gone. Each
/// check that passes sets one bit of [`OVERLAY_SELFTEST`]; the scratch subtree is removed, so the
/// mounted volume has the same node occupancy after the probe that it had before the probe.
///
/// It runs on `\.fsselftest\…`, deliberately NOT under any [`WRITABLE_PREFIXES`] entry, so no
/// hosted-process syscall can reach it and — crucially — it leaves preexisting mounted state
/// untouched: on a first boot `\profiles` is still absent, while on a restored boot no persisted node
/// is added or removed.
fn selftest(fs: &mut nt_fs::FileSystem) {
    const DIR: &str = r"\??\C:\.fsselftest";
    const FILE: &str = r"\??\C:\.fsselftest\probe.bin";
    const PAYLOAD: &[u8] = b"writable overlay probe";
    let mut bits = 0u64;
    let initial_nodes = fs.node_count();

    // (1) A real directory create.
    let dir = fs.zw_create_file(
        DIR,
        nt_fs::FILE_WRITE_DATA,
        0,
        0,
        nt_fs::FILE_CREATE,
        nt_fs::FILE_DIRECTORY_FILE,
    );
    if dir.status == nt_fs::STATUS_SUCCESS && dir.information == nt_fs::FILE_CREATED {
        bits |= 1 << 0;
    }
    // (2) Creating it AGAIN collides — the FS has real state, it is not answering yes to everything.
    let dup = fs.zw_create_file(
        DIR,
        nt_fs::FILE_WRITE_DATA,
        0,
        0,
        nt_fs::FILE_CREATE,
        nt_fs::FILE_DIRECTORY_FILE,
    );
    if dup.status == nt_fs::STATUS_OBJECT_NAME_COLLISION {
        bits |= 1 << 1;
    }
    // (3) A real file create + (4) write + (5) read-back of the same bytes.
    let file = fs.zw_create_file(
        FILE,
        nt_fs::FILE_WRITE_DATA | nt_fs::FILE_READ_DATA,
        0,
        0,
        nt_fs::FILE_CREATE,
        nt_fs::FILE_NON_DIRECTORY_FILE,
    );
    if file.status == nt_fs::STATUS_SUCCESS && file.information == nt_fs::FILE_CREATED {
        bits |= 1 << 2;
        let (write_status, written) = fs.zw_write_file(file.handle, Some(0), PAYLOAD);
        if write_status == nt_fs::STATUS_SUCCESS && written == PAYLOAD.len() {
            bits |= 1 << 3;
        }
        let (read_status, bytes) = fs.zw_read_file(file.handle, Some(0), PAYLOAD.len());
        if read_status == nt_fs::STATUS_SUCCESS && bytes == PAYLOAD {
            bits |= 1 << 4;
        }
        // (6) The metadata agrees with what was written.
        if let Some(info) = fs.zw_query_standard_information(file.handle) {
            if info.end_of_file == PAYLOAD.len() as u64 && !info.is_directory {
                bits |= 1 << 5;
            }
        }
        fs.zw_close(file.handle);
    }
    if dir.status == nt_fs::STATUS_SUCCESS {
        fs.zw_close(dir.handle);
    }
    // (7) Enumeration through the native record encoder finds `.`, `..` and the file.
    let scan = fs.zw_create_file(
        DIR,
        nt_fs::FILE_READ_DATA,
        0,
        0,
        nt_fs::FILE_OPEN,
        nt_fs::FILE_DIRECTORY_FILE,
    );
    if scan.status == nt_fs::STATUS_SUCCESS {
        let mut buffer = [0u8; 1024];
        let result = fs.zw_query_directory_file(
            scan.handle,
            nt_fs::FILE_DIRECTORY_INFORMATION,
            false,
            None,
            true,
            &mut buffer,
        );
        if result.status == nt_fs::STATUS_SUCCESS {
            let mut offset = 0usize;
            let mut names = 0u32;
            let mut found_probe = false;
            loop {
                if offset + 64 > result.information {
                    break;
                }
                let next =
                    u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
                let name_len =
                    u32::from_le_bytes(buffer[offset + 60..offset + 64].try_into().unwrap())
                        as usize;
                let name = &buffer[offset + 64..(offset + 64 + name_len).min(buffer.len())];
                names += 1;
                if name.len() == b"probe.bin".len() * 2
                    && name
                        .chunks(2)
                        .map(|c| c[0])
                        .eq(b"probe.bin".iter().copied())
                {
                    found_probe = true;
                }
                if next == 0 {
                    break;
                }
                offset += next;
            }
            if names == 3 && found_probe {
                bits |= 1 << 6;
            }
        }
        fs.zw_close(scan.handle);
    }
    // (8) Delete-on-close really unlinks: the file, then the (now empty) directory, and a
    // by-path attribute query for each must MISS afterwards.
    let del_file = fs.zw_create_file(
        FILE,
        nt_fs::FILE_WRITE_DATA | nt_fs::DELETE,
        0,
        0,
        nt_fs::FILE_OPEN,
        nt_fs::FILE_DELETE_ON_CLOSE,
    );
    if del_file.status == nt_fs::STATUS_SUCCESS {
        fs.zw_close(del_file.handle);
    }
    let del_dir = fs.zw_create_file(
        DIR,
        nt_fs::FILE_WRITE_DATA | nt_fs::DELETE,
        0,
        0,
        nt_fs::FILE_OPEN,
        nt_fs::FILE_DIRECTORY_FILE | nt_fs::FILE_DELETE_ON_CLOSE,
    );
    if del_dir.status == nt_fs::STATUS_SUCCESS {
        fs.zw_close(del_dir.handle);
    }
    if fs.query_attributes(FILE).is_none() && fs.query_attributes(DIR).is_none() {
        bits |= 1 << 7;
    }
    // (9) …and the volume is back to the exact occupancy it had before the scratch probe.
    if fs.node_count() == initial_nodes {
        bits |= 1 << 8;
    }
    OVERLAY_SELFTEST.store(bits, Ordering::Relaxed);
    print_str(b"[writable-fs] mounted: MemFs over prefixes=");
    print_u64(WRITABLE_PREFIXES.len() as u64);
    print_str(b" selftest=0x");
    print_hex(bits as u32);
    print_str(b" nodes=");
    print_u64(fs.node_count() as u64);
    print_str(b"\n");
}

/// Every bit [`selftest`] can set — the value `OVERLAY_SELFTEST` must hold for the volume to be
/// certified as a real read/write/enumerate/delete filesystem.
pub(crate) const OVERLAY_SELFTEST_ALL: u64 = 0x1FF;
