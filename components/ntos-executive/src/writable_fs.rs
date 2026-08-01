//! `writable_fs` — the executive's WRITABLE filesystem overlay.
//!
//! ## What this is
//!
//! The `\reactos` volume the hosted processes boot off is a **read-only** FAT32 reader
//! (`fs_loader`): it can resolve any path to bytes, and nothing more. Everything a real NT session
//! does the moment a user logs on — `CreateDirectoryW("C:\Profiles")`, writing a profile, creating
//! `ntuser.dat` — needs a filesystem that can be WRITTEN. Without one, `NtCreateFile` on those
//! paths returned `STATUS_NOT_IMPLEMENTED` (⇒ `GetLastError() == 1`) and `CreateUserProfileW`
//! failed at `userenv/profile.c:929`.
//!
//! This module mounts a **real** filesystem over the writable part of the namespace. Real means
//! real: create/open with every disposition, `FILE_DIRECTORY_FILE`, read, write at an offset or at
//! the file-object's own position, query/set information, directory ENUMERATION (`.`, `..`, the
//! children), delete-on-close, and the correct NTSTATUS for each miss. Nothing here fabricates a
//! success — a `CreateDirectory` that this volume cannot satisfy still fails.
//!
//! ## The seam
//!
//! * **Namespace.** A path belongs to the writable volume iff its canonical volume-relative form
//!   (the SAME [`nt_fs::nt_path_to_volume_relative`] canonicalisation the read-only reader uses) is
//!   at or under one of [`WRITABLE_PREFIXES`]. That is the general "writable mount at prefix P"
//!   mechanism ([`nt_fs::writable_mount_relative`]) — adding a writable subtree is one entry in
//!   that table, not a new code path, and nothing outside those prefixes changes behaviour.
//! * **Backing.** [`nt_fs::MemFs`] behind the [`nt_fs::FileSystem`] `Zw*` facade — RAM-backed and
//!   therefore **not persistent across boots**, which is a deliberate, user-approved staging step.
//!   Persisting these writes through to FAT32 is a separate, tracked milestone; when it lands only
//!   the backing behind this module changes, because every caller is above the `Zw*` seam.
//! * **Handles.** An open file object is owned by a per-process `nt-process` handle
//!   (`HandleObject::OverlayFile`), so it is closable, duplicable and reclaimed with the process
//!   like every other executive object.

use crate::*;

/// The namespace subtrees served by the writable volume, as canonical volume-relative paths
/// (lowercase, `\`-separated, no leading separator — the form `nt_path_to_volume_relative` emits).
///
/// `profiles` is `%SystemDrive%\Profiles`, the `ProfilesDirectory` the real SOFTWARE hive names and
/// the tree winlogon's `LoadUserProfileW` → `CreateUserProfileW` builds. It is deliberately narrow:
/// everything else — above all `\reactos\…`, which carries the entire boot — keeps resolving
/// through the read-only FAT reader, untouched.
pub(crate) const WRITABLE_PREFIXES: &[&[u8]] = &[b"profiles"];

/// ★ BYPASS SWITCH (the batch's control experiment). `false` unmounts the writable volume: every
/// path below falls back to the pre-existing `STATUS_NOT_IMPLEMENTED` miss, `CreateDirectoryW`
/// returns `Error: 1` again and the overlay specs go red. Nothing else in the executive changes.
pub(crate) const WRITABLE_OVERLAY_MOUNTED: bool = true;

/// ★ THE PROFILE SOURCE — **the ISO's OWN `Profiles/` tree, which our staging was dropping.**
///
/// `CreateUserProfileExW` seeds a new user's profile by COPYING `C:\Profiles\Default User`
/// (`profile.c:1000` → `CopyDirectory` → `FindFirstFileW("C:\Profiles\Default User\*.*")`), and
/// that copy failed at `profile.c:1002  Error: 3` (ERROR_PATH_NOT_FOUND) because the image had no
/// profile tree at all.
///
/// The tree was NOT missing from the media — it was missing from OUR STAGING. The ReactOS LiveCD
/// ISO carries a real 76-entry `Profiles/` tree (`Default User/…`, `All Users/…`) as a **top-level
/// sibling of `reactos/`**, and every extraction in `fetch_reactos.sh` was scoped to `reactos`, so
/// it never reached the disk image. `fetch_reactos.sh` now extracts it and `make_image.sh` lays it
/// down at `::Profiles` — exactly where `%SystemDrive%\Profiles` (the real SOFTWARE hive's
/// `ProfileList\ProfilesDirectory`) resolves. Nothing is synthesised: these are the ISO's own
/// directories and files, byte for byte.
///
/// **Composition with the writable volume.** `C:\Profiles` is a writable-volume prefix
/// ([`WRITABLE_PREFIXES`]) while the staged tree is on the READ-ONLY FAT volume, so the two must
/// compose. The chosen composition is **materialise-at-mount**: when the writable volume is first
/// touched, the executive walks the staged `\Profiles` tree off the FAT volume and recreates it —
/// directories AND file contents — on the writable volume. That was picked over a union/read-through
/// layer because it is strictly simpler and leaves ONE code path: after mount every hosted-process
/// syscall sees a single, coherent, writable `C:\Profiles`, so `CopyDirectory` can enumerate and
/// read the source and write the destination with no per-operation layer arbitration, and a later
/// FAT32 write-through milestone replaces the backing without touching any of it. The cost is the
/// tree's bytes in RAM, which for this tree is ~76 nodes and ~360 bytes of file content.
///
/// ★ **ON since batch 58.** It shipped `false` for one batch on the belief that the profile flow
/// blew the TCG time budget ("post-logon UI work grows ~2.5x"). That was WRONG: host-side
/// timestamps showed the boot going COMPLETELY SILENT for the last 245 s behind a blocking
/// `NtUserGetMessage` that win32k could never answer — a deadlock, not a budget. With that fixed
/// (see `GET_MESSAGE_EMPTY_QUEUE_GUARD`) the boot quiesces in 319-329 s of the ~555 s window with
/// the flow ON, and `userenv!CopyDirectory` really runs: 20 subdirectories created below
/// `C:\Profiles\<user>` and 2 files copied byte-exact from the ISO's `Default User`
/// (`exec_winlogon_profile_copied`). Materialisation itself is unchanged and still measured at
/// `dirs=45 files=31 bytes=5307` with `Default User` enumerating its real 17 records.
pub(crate) const PROVISION_DEFAULT_USER_PROFILE: bool = true;

/// ★ THE SETUP STEP THE LIVECD SKIPS — `Default User\ntuser.dat`, from GENUINE ReactOS data.
///
/// `CreateUserProfileExW` copies `C:\Profiles\Default User` into the new profile and then calls
/// `RegLoadKeyW(HKEY_USERS, <SID>, "<profile>\ntuser.dat")` (`profile.c:1088`). On this image that
/// returned **`Error: 2` (ERROR_FILE_NOT_FOUND)**: there is **no `ntuser.dat` anywhere on the
/// ISO**, because a LiveCD never runs the setup step that creates one — ReactOS setup
/// (`base/setup/lib/registry.c`, `CreateUserHive`/`InstallHives`) copies
/// `system32\config\default` — the `$$$PROTO.HIV` prototype, i.e. the very hive the kernel mounts
/// as `HKEY_USERS\.DEFAULT` — into the Default User profile as `ntuser.dat`. This performs THAT
/// step, with THAT file: the 139264 bytes the storage host already read BY PATH off
/// `\reactos\system32\config\default` into `DEFHIVEBUF` ([`default_hive_bytes`]). Nothing is
/// synthesised and nothing is fabricated — it is the image's own regf, byte for byte.
///
/// **Why the `Default User` profile and not the user's.** winlogon must stay the actor: dropping
/// the file into `C:\Profiles\Administrator` directly would make `LoadUserProfileW`'s
/// `GetFileAttributesW(<profile>\ntuser.dat)` probe (`profile.c:2088`) SUCCEED, which SKIPS
/// `CreateUserProfileW` entirely — no `CreateDirectoryW`, no `CopyDirectory`, i.e. it would delete
/// the very behaviour `exec_winlogon_profile_directories_created` and
/// `exec_winlogon_profile_copied` measure. Placed in the SOURCE profile instead, winlogon's own
/// `CopyDirectory` → `CopyFileW` carries it across, through the real `NtCreateFile`/`NtReadFile`/
/// `NtWriteFile` path, and the destination hive is winlogon's own output.
///
/// ★ BYPASS SWITCH: `false` restores the pre-batch state — the copied profile has no `ntuser.dat`
/// and `RegLoadKeyW` returns `Error: 2` again (`exec_profile_ntuser_dat_present` FAILs).
pub(crate) const PROVISION_NTUSER_DAT: bool = true;

/// The `ntuser.dat` leaf, its source profile, and the destination the copy must produce.
pub(crate) const NTUSER_DAT_LEAF: &str = "ntuser.dat";
pub(crate) const DEFAULT_USER_NTUSER_DAT: &str = r"\??\C:\Profiles\Default User\ntuser.dat";
pub(crate) const COPIED_PROFILE_NTUSER_DAT: &str = r"\??\C:\Profiles\Administrator\ntuser.dat";

/// Bytes of the `ntuser.dat` really provisioned into the `Default User` profile (0 = not present).
pub(crate) static NTUSER_DAT_PROVISIONED: AtomicU64 = AtomicU64::new(0);

/// Is `path` a REAL regf hive on this volume? Checked by CONTENT, not by existence: the bytes must
/// parse through the same `nt-hive-regf` navigator the registry mounts a hive with, AND its root
/// must really enumerate subkeys (a zero-filled or truncated file cannot fake that). Returns the
/// hive's byte length, or 0.
pub(crate) fn regf_len_on(fs: &nt_fs::FileSystem, path: &str) -> usize {
    let Some(bytes) = fs.file_bytes(path) else {
        return 0;
    };
    match RegfHive::new(bytes) {
        Some(hive) if !hive.subkeys(hive.root()).is_empty() => bytes.len(),
        _ => 0,
    }
}

/// [`regf_len_on`] against the LIVE mounted volume (the gate specs' read-back).
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the read.
pub(crate) unsafe fn regf_len_at(path: &str) -> usize {
    match writable_fs() {
        Some(fs) => regf_len_on(fs, path),
        None => 0,
    }
}

/// The staged tree's FAT root name, and its mount point on the writable volume.
pub(crate) const STAGED_PROFILES_DIR: &[u8] = b"Profiles";
pub(crate) const PROFILES_VOLUME_ROOT: &str = r"\??\C:\Profiles";
/// The profile-source directory `CreateUserProfileExW` copies, and a REAL file inside it whose
/// content the spec reads back (`livecd_start.cmd` is 9 bytes: `@start %1`).
pub(crate) const DEFAULT_USER_PROFILE_DIR: &str = r"\??\C:\Profiles\Default User";
pub(crate) const DEFAULT_USER_PROBE_FILE: &str =
    r"\??\C:\Profiles\Default User\My Documents\livecd_start.cmd";

/// The DESTINATION path `CopyDirectory` must have produced for the probe file, and the source
/// bytes it must contain. The user directory is the real profile name `CreateUserProfileExW`
/// derived from the logged-on account, so this is the copy's own output path, not a fabrication.
pub(crate) const COPIED_PROFILE_PROBE_FILE: &str =
    r"\??\C:\Profiles\Administrator\My Documents\livecd_start.cmd";

/// Whether `CopyDirectory` really wrote the SOURCE file's exact bytes to its DESTINATION path —
/// read back off the LIVE writable volume, by content.
///
/// # Safety
/// Single-threaded executive; borrows the mounted volume for the duration of the read.
pub(crate) unsafe fn copied_profile_probe_ok() -> bool {
    match writable_fs() {
        Some(fs) => fs.file_bytes(COPIED_PROFILE_PROBE_FILE) == Some(b"@start %1"),
        None => false,
    }
}

/// Directories / files / content bytes really materialised from the staged `\Profiles` tree.
pub(crate) static PROFILE_SOURCE_DIRS: AtomicU64 = AtomicU64::new(0);
pub(crate) static PROFILE_SOURCE_FILES: AtomicU64 = AtomicU64::new(0);
pub(crate) static PROFILE_SOURCE_BYTES: AtomicU64 = AtomicU64::new(0);
/// A REAL staged file's content, read back off the LIVE volume (`livecd_start.cmd` == `@start %1`).
pub(crate) static PROFILE_SOURCE_PROBE_OK: AtomicU64 = AtomicU64::new(0);
/// Directory entries `Default User` really enumerates (`.`, `..` + its 15 real children), read back
/// through the SAME `Zw*` record encoder `NtQueryDirectoryFile` — and so `FindFirstFileW` — uses.
pub(crate) static PROFILE_SOURCE_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// The mounted writable volume. `None` until the first path resolves into it (the volume is
/// created lazily so a boot that never writes pays nothing).
static mut EXEC_WRITABLE_FS: Option<nt_fs::FileSystem> = None;

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
    if relative == b"profiles" {
        if created {
            PROFILE_ROOT_CREATED.fetch_add(1, Ordering::Relaxed);
        } else {
            PROFILE_ROOT_COLLIDED.fetch_add(1, Ordering::Relaxed);
        }
    } else if created && depth == 1 && relative.starts_with(b"profiles\\") {
        PROFILE_USER_DIR_CREATED.fetch_add(1, Ordering::Relaxed);
    } else if created && depth >= 2 && relative.starts_with(b"profiles\\") {
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
        && relative.starts_with(b"profiles\\")
        && relative.iter().filter(|byte| **byte == b'\\').count() >= 2
    {
        PROFILE_COPY_FILES.fetch_add(1, Ordering::Relaxed);
    }
}

/// The live writable volume, mounting it on first use. `None` when the overlay is bypassed.
///
/// # Safety
/// Single-threaded executive; the returned reference must not outlive the calling syscall service.
pub(crate) unsafe fn writable_fs() -> Option<&'static mut nt_fs::FileSystem> {
    if !WRITABLE_OVERLAY_MOUNTED {
        return None;
    }
    let slot = &mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS);
    if slot.is_none() {
        *slot = Some(nt_fs::FileSystem::new(nt_fs::MemFs::new()));
        let fs = slot.as_mut().unwrap();
        selftest(fs);
        if PROVISION_DEFAULT_USER_PROFILE {
            provision_staged_profiles(fs);
        }
    }
    slot.as_mut()
}

/// Whether the volume has been mounted (i.e. something actually resolved into it).
pub(crate) unsafe fn writable_fs_mounted() -> bool {
    (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_some()
}

/// The volume's own NT path for a canonical volume-relative path. The writable volume is rooted at
/// the DOS drive, so `profiles\administrator` ⇒ `\??\C:\profiles\administrator`.
fn volume_path(relative: &[u8]) -> alloc::string::String {
    let mut path = alloc::string::String::from(r"\??\C:\");
    for &byte in relative {
        path.push(byte as char);
    }
    path
}

/// Classify an NT object name: `Some(volume-relative path)` when it belongs to the writable volume,
/// `None` when the read-only namespace still owns it.
pub(crate) fn writable_path(name: &[u16]) -> Option<alloc::vec::Vec<u8>> {
    if !WRITABLE_OVERLAY_MOUNTED {
        return None;
    }
    nt_fs::writable_mount_relative(name, b"reactos", WRITABLE_PREFIXES)
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
    let Some(fs) = writable_fs() else {
        return (nt_fs::STATUS_NOT_IMPLEMENTED, None, 0);
    };
    let result = fs.zw_create_file(
        &volume_path(relative),
        desired_access,
        file_attributes,
        share_access,
        disposition,
        options,
    );
    if result.status == nt_fs::STATUS_SUCCESS {
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

/// `NtQueryAttributesFile` — by PATH, no file object. `None` when the path does not exist.
pub(crate) unsafe fn query_attributes(relative: &[u8]) -> Option<nt_fs::StandardInformation> {
    OVERLAY_ATTR_QUERIES.fetch_add(1, Ordering::Relaxed);
    let fs = writable_fs()?;
    let info = fs.query_attributes(&volume_path(relative))?;
    OVERLAY_ATTR_HITS.fetch_add(1, Ordering::Relaxed);
    Some(info)
}

/// `NtReadFile` on a writable-volume file object.
pub(crate) unsafe fn read(
    file_id: u64,
    byte_offset: Option<u64>,
    length: usize,
) -> (u32, alloc::vec::Vec<u8>) {
    let Some(fs) = writable_fs() else {
        return (nt_fs::STATUS_INVALID_HANDLE, alloc::vec::Vec::new());
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

/// `NtWriteFile` on a writable-volume file object.
pub(crate) unsafe fn write(file_id: u64, byte_offset: Option<u64>, data: &[u8]) -> (u32, usize) {
    let Some(fs) = writable_fs() else {
        return (nt_fs::STATUS_INVALID_HANDLE, 0);
    };
    let (status, written) = fs.zw_write_file(file_id, byte_offset, data);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
        OVERLAY_BYTES_WRITTEN.fetch_add(written as u64, Ordering::Relaxed);
    } else {
        trace_io_refusal(b"write", file_id, byte_offset, data.len(), status);
    }
    (status, written)
}

/// `NtQueryInformationFile` metadata for a writable-volume file object.
pub(crate) unsafe fn standard_information(file_id: u64) -> Option<nt_fs::StandardInformation> {
    writable_fs()?.zw_query_standard_information(file_id)
}

/// `NtSetInformationFile` on a writable-volume file object.
pub(crate) unsafe fn set_information(file_id: u64, class: u32, data: &[u8]) -> u32 {
    let Some(fs) = writable_fs() else {
        return nt_fs::STATUS_INVALID_HANDLE;
    };
    let status = fs.zw_set_information_file(file_id, class, data);
    if status == nt_fs::STATUS_SUCCESS {
        OVERLAY_SET_INFO.fetch_add(1, Ordering::Relaxed);
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
    let Some(fs) = writable_fs() else {
        return nt_fs::DirectoryQueryResult {
            status: nt_fs::STATUS_INVALID_HANDLE,
            information: 0,
        };
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
    let Some(fs) = writable_fs() else {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    };
    match fs.zw_retain(file_id) {
        nt_fs::STATUS_SUCCESS => Ok(()),
        status => Err(status),
    }
}

/// `NtClose` on a writable-volume file object (honours a pending delete).
pub(crate) unsafe fn close(file_id: u64) {
    if let Some(fs) = writable_fs() {
        if fs.zw_close(file_id) == nt_fs::STATUS_SUCCESS {
            OVERLAY_CLOSES.fetch_add(1, Ordering::Relaxed);
        }
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
    // Explicit DFS stack (no recursion in the executive): (fat cluster, volume path of the dir).
    const MAX_DEPTH: u32 = 12;
    let mut stack: alloc::vec::Vec<(u32, alloc::string::String, u32)> = alloc::vec::Vec::new();
    let _ = fs.provision_directory(PROFILES_VOLUME_ROOT);
    stack.push((
        root_cluster,
        alloc::string::String::from(PROFILES_VOLUME_ROOT),
        0,
    ));
    let (mut dirs, mut files, mut bytes) = (0u64, 0u64, 0u64);
    while let Some((cluster, base, depth)) = stack.pop() {
        // Collect this directory's children first: `fat_visit_directory` and `dir_find_lfn` both
        // drive the sector cache, so the names are captured before any further reads.
        let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
        crate::fs_loader::fat_visit_directory(&fat, cluster, |entry| {
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
                crate::fs_loader::dir_find_lfn(&fat, cluster, name.as_bytes())
            else {
                continue;
            };
            let mut path = base.clone();
            path.push('\\');
            path.push_str(&name);
            if child_attr & 0x10 != 0 {
                if fs.provision_directory(&path) {
                    dirs += 1;
                    if depth + 1 < MAX_DEPTH {
                        stack.push((child, path, depth + 1));
                    }
                }
            } else if size as usize <= MAX_STAGED_FILE {
                let mut data = alloc::vec::Vec::new();
                if data.try_reserve_exact(size as usize).is_err() {
                    continue;
                }
                data.resize(size as usize, 0);
                let got = if size == 0 {
                    0
                } else {
                    crate::fs_loader::fat_read_file(&fat, child, size, data.as_mut_ptr() as u64)
                };
                if got == size && fs.provision_file(&path, &data) {
                    files += 1;
                    bytes += size as u64;
                }
            }
        }
    }
    PROFILE_SOURCE_DIRS.store(dirs, Ordering::Relaxed);
    PROFILE_SOURCE_FILES.store(files, Ordering::Relaxed);
    PROFILE_SOURCE_BYTES.store(bytes, Ordering::Relaxed);
    // Read a REAL staged file back off the live volume, by content.
    if fs.file_bytes(DEFAULT_USER_PROBE_FILE) == Some(b"@start %1") {
        PROFILE_SOURCE_PROBE_OK.store(1, Ordering::Relaxed);
    }
    // ★ THE SETUP STEP THE LIVECD SKIPS (see `PROVISION_NTUSER_DAT`): give the `Default User`
    // profile the `ntuser.dat` setup would have made for it, from the image's OWN
    // `system32\config\default` regf. Done here, on the SOURCE profile, so winlogon's own
    // `CopyDirectory` is what puts it in the user's profile.
    if PROVISION_NTUSER_DAT {
        match default_hive_bytes() {
            Some(hive) if RegfHive::new(hive).is_some() => {
                if fs.provision_file(DEFAULT_USER_NTUSER_DAT, hive) {
                    files += 1;
                    bytes += hive.len() as u64;
                    NTUSER_DAT_PROVISIONED.store(hive.len() as u64, Ordering::Relaxed);
                }
            }
            _ => print_str(b"[profile-source] config\\default NOT staged -> no ntuser.dat\n"),
        }
        PROFILE_SOURCE_DIRS.store(dirs, Ordering::Relaxed);
        PROFILE_SOURCE_FILES.store(files, Ordering::Relaxed);
        PROFILE_SOURCE_BYTES.store(bytes, Ordering::Relaxed);
    }
    PROFILE_SOURCE_ENTRIES.store(
        count_entries(fs, DEFAULT_USER_PROFILE_DIR),
        Ordering::Relaxed,
    );
    print_str(b"[profile-source] materialised ::Profiles onto the writable volume: dirs=");
    print_u64(dirs);
    print_str(b" files=");
    print_u64(files);
    print_str(b" bytes=");
    print_u64(bytes);
    print_str(b" `Default User` dir-entries=");
    print_u64(PROFILE_SOURCE_ENTRIES.load(Ordering::Relaxed));
    print_str(b" probe-file-content-ok=");
    print_u64(PROFILE_SOURCE_PROBE_OK.load(Ordering::Relaxed));
    print_str(b" ntuser.dat=");
    print_u64(NTUSER_DAT_PROVISIONED.load(Ordering::Relaxed));
    print_str(b"B(regf-ok=");
    // Read it back off the LIVE volume and parse it, so the claim "a real regf is in the source
    // profile" is measured through the same navigator the registry will mount it with.
    print_u64(regf_len_on(fs, DEFAULT_USER_NTUSER_DAT) as u64);
    print_str(b")\n");
}

/// The largest staged profile file the executive will materialise (the whole tree is ~360 bytes;
/// this is a guard against a future tree dragging bulk data onto the bump heap).
const MAX_STAGED_FILE: usize = 256 * 1024;

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
/// volume is left EMPTY (just its root) for the hosted processes.
///
/// It runs on `\.fsselftest\…`, deliberately NOT under any [`WRITABLE_PREFIXES`] entry, so no
/// hosted-process syscall can reach it and — crucially — `\profiles` is left untouched: when
/// winlogon later creates `C:\Profiles` it is genuinely the creator.
fn selftest(fs: &mut nt_fs::FileSystem) {
    const DIR: &str = r"\??\C:\.fsselftest";
    const FILE: &str = r"\??\C:\.fsselftest\probe.bin";
    const PAYLOAD: &[u8] = b"writable overlay probe";
    let mut bits = 0u64;

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
        nt_fs::FILE_WRITE_DATA,
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
        nt_fs::FILE_WRITE_DATA,
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
    // (9) …and the volume is back to exactly its root: the self-test left nothing behind, so
    // `\profiles` is still absent and winlogon's create will genuinely be the creating one.
    if fs.node_count() == 1 {
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
