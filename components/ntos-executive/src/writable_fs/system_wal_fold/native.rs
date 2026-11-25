//! Retained native SYSTEM fold: two identical snapshots, optional WAL rollover, CM ACK.

use super::*;
use alloc::vec::Vec;
use nt_memory_manager::SectionMountId;
use nt_fs::{AsyncSnapshotCommit, AsyncSnapshotIoKind, AsyncSnapshotRequest,
    AsyncWalEpochRollover};

type Commit = AsyncSnapshotCommit<snapshot_capture::CapturedSnapshot>;

enum Cursor { First(Commit), Second(Commit), Rollover(AsyncWalEpochRollover) }

impl Cursor {
    fn enter_next(&mut self) -> Result<Option<AsyncSnapshotRequest>, nt_fs::AsyncSnapshotCommitError> {
        match self { Self::First(c) | Self::Second(c) => c.enter_next(), Self::Rollover(c) => c.enter_next() }
    }
    fn pending(&self) -> Option<AsyncSnapshotRequest> {
        match self { Self::First(c) | Self::Second(c) => c.pending(), Self::Rollover(c) => c.pending() }
    }
    fn is_done(&self) -> bool {
        match self { Self::First(c) | Self::Second(c) => c.is_done(), Self::Rollover(c) => c.is_done() }
    }
    fn write_bytes(&self, request: AsyncSnapshotRequest) -> Option<&[u8]> {
        match self { Self::First(c) | Self::Second(c) => c.write_bytes(request), Self::Rollover(c) => c.write_bytes(request) }
    }
    fn release_unentered(&mut self, request: AsyncSnapshotRequest)
        -> Result<(), nt_fs::AsyncSnapshotCommitError> {
        match self { Self::First(c) | Self::Second(c) => c.release_unentered(request),
            Self::Rollover(c) => c.release_unentered(request) }
    }
    fn lose(&mut self, request: AsyncSnapshotRequest) {
        match self { Self::First(c) | Self::Second(c) => { let _ = c.lose(request); },
            Self::Rollover(c) => { let _ = unsafe { c.complete(request, false) }; } }
    }
    unsafe fn complete(&mut self, request: AsyncSnapshotRequest, bytes: &[u8])
        -> Result<(), nt_fs::AsyncSnapshotCommitError> {
        match self {
            Self::First(c) | Self::Second(c) => match request.kind {
                AsyncSnapshotIoKind::Read => c.complete_read(request, bytes),
                _ if bytes.is_empty() => c.complete_effect(request, request.bytes),
                _ => Err(nt_fs::AsyncSnapshotCommitError::Incomplete),
            },
            Self::Rollover(c) if bytes.is_empty() => unsafe { c.complete(request, true) },
            Self::Rollover(_) => Err(nt_fs::AsyncSnapshotCommitError::Incomplete),
        }
    }
}

struct Active {
    id: u64,
    started_ticks: u64,
    start_after_print: bool,
    trace: bool,
    write_sectors: u64,
    prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
    lease: snapshot_storage::Lease,
    token: nt_fs::RegistryWalContinuation,
    old_pair: Option<nt_fs::VerifiedPairedWalSnapshot>,
    manifest: nt_fs::WalSnapshotManifest,
    bytes: usize,
    cursor: Option<Cursor>,
    entered: bool,
    failed: bool,
}

enum StalledState {
    Admission {
        _lease: Option<snapshot_storage::Lease>,
        _prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
        _mount: SectionMountId,
        _manifest: nt_fs::WalSnapshotManifest,
    },
    BeforeCommit {
        _lease: snapshot_storage::Lease,
        _token: nt_fs::RegistryWalContinuation,
        _pair: nt_fs::VerifiedPairedWalSnapshot,
        _image: Option<snapshot_capture::CapturedSnapshot>,
        _prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
    },
    // An entered or uncertain request retains the cursor, request ID, lease and proof.
    Active(Active),
    SecondAdmission {
        _active: Active,
        _image: snapshot_capture::CapturedSnapshot,
        _pair: nt_fs::VerifiedPairedWalSnapshot,
    },
}

enum Work {
    /// No header read entered. CM's prepared image remains single-flight while a timer-only
    /// retry reacquires this same mounted reserve and validates its latest WAL proof.
    AdmissionPending {
        prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
        manifest: nt_fs::WalSnapshotManifest,
        mount: SectionMountId,
        retry_after_100ns: u64,
        last_status: u32,
    },
    Rechecking { id: u64, prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
        manifest: nt_fs::WalSnapshotManifest, mount: SectionMountId, started_ticks: u64,
        start_after_print: bool, trace: bool },
    Active(Active),
    // A local contradiction retains every move-only owner until boot recovery.
    Stalled(StalledState),
}

static mut WORK: Option<Work> = None;
const ADMISSION_RETRY_100NS: u64 = 5 * 10_000_000;
static FOLD_MEASURES: AtomicU64 = AtomicU64::new(0);
static FOLD_MEASURE_LIMIT_REPORTED: AtomicBool = AtomicBool::new(false);

fn reserve_trace() -> bool {
    const LIMIT: u64 = 512;
    FOLD_MEASURES.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |used| (used < LIMIT).then_some(used + 1)).is_ok()
}

fn trace_started(id: u64, manifest: nt_fs::WalSnapshotManifest, trace: bool) {
    if trace {
        print_str(b"[writable-fs-fold-measure] begin id/base/high-water=");
        for value in [id, manifest.base_serial, manifest.high_water_serial] {
            print_str(b"/"); print_u64(value);
        }
        print_str(b"\n");
    } else if !FOLD_MEASURE_LIMIT_REPORTED.swap(true, Ordering::AcqRel) {
        print_str(b"[writable-fs-fold-measure] trace-limit-exhausted=512\n");
    }
}

pub(super) unsafe fn print_quiesce_owner() {
    let work = (&*core::ptr::addr_of!(WORK)).as_ref();
    print_str(b"[quiesce-native-fold] phase=");
    print_str(match work {
        None => b"absent",
        Some(Work::AdmissionPending { .. }) => b"admission-pending",
        Some(Work::Rechecking { .. }) => b"rechecking",
        Some(Work::Active(_)) => b"active",
        Some(Work::Stalled(_)) => b"stalled",
    });
    let (id, lease, entered, failed) = match work {
        Some(Work::AdmissionPending { .. }) => (0, false, false, false),
        Some(Work::Rechecking { id, .. }) => (*id, false, false, false),
        Some(Work::Active(active)) =>
            (active.id, true, active.entered, active.failed),
        Some(Work::Stalled(_)) => (0, true, false, true),
        None => (0, false, false, false),
    };
    print_str(b" id="); print_u64(id);
    print_str(b" local-lease="); print_u64(u64::from(lease));
    print_str(b" entered="); print_u64(u64::from(entered));
    print_str(b" failed="); print_u64(u64::from(failed));
    if let Some(Work::AdmissionPending { last_status, .. }) = work {
        print_str(b" admission-refusal=0x"); print_hex(*last_status);
    }
    print_str(b"\n");
}

#[must_use = "retain through native provider terminal and ACK"]
pub(crate) struct FoldTicket { id: u64, request: AsyncSnapshotRequest }

fn fold_manifest(old: nt_fs::WalSnapshotManifest) -> nt_fs::WalSnapshotManifest {
    nt_fs::WalSnapshotManifest { incarnation: old.incarnation,
        base_serial: old.high_water_serial, high_water_serial: old.high_water_serial,
        high_water_end_lba: old.high_water_end_lba }
}

fn stall_before_commit(
    slot: &mut Option<Work>, lease: snapshot_storage::Lease,
    token: nt_fs::RegistryWalContinuation, proof: nt_fs::RecheckedPairedWalSnapshot,
    prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
    image: Option<snapshot_capture::CapturedSnapshot>, status: u32,
) -> u32 {
    *slot = Some(Work::Stalled(StalledState::BeforeCommit {
        _lease: lease, _token: token, _pair: proof.into_pair(), _image: image,
        _prepared: prepared,
    }));
    block(status)
}

unsafe fn advance_recheck() -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Rechecking { id, .. }) = slot.as_ref() else { return Ok(()); };
    let id = *id;
    let (lease, token, proof) = match snapshot_storage::take_rechecked_wal_continuation(id) {
        Ok(Some(parts)) => parts,
        Ok(None) => return Err(snapshot_storage::BUSY),
        Err(status) => {
            if snapshot_storage::recheck_was_aborted_no_effect(id) {
                let Some(Work::Rechecking { prepared, manifest, mount, .. }) = slot.take()
                    else { unreachable!() };
                *slot = Some(Work::AdmissionPending { prepared, manifest, mount,
                    retry_after_100ns: crate::monotonic_time_100ns()
                        .saturating_add(ADMISSION_RETRY_100NS),
                    last_status: status });
                return Err(snapshot_storage::BUSY);
            }
            return Err(status);
        }
    };
    let Some(Work::Rechecking { prepared, manifest, started_ticks,
        start_after_print, trace, .. }) = slot.take()
        else { unreachable!() };
    if proof.manifest() != manifest || proof.anchor() != token.anchor() {
        return Err(stall_before_commit(slot, lease, token, proof, prepared, None,
            nt_fs::STATUS_DATA_ERROR));
    }
    let Some(fs) = (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).as_ref() else {
        return Err(stall_before_commit(slot, lease, token, proof, prepared, None,
            nt_fs::STATUS_DEVICE_NOT_READY));
    };
    // Derive an independent volume from the exact resident image. It has its own node tree,
    // mount manager, and empty handle table; only this private volume sees the prepared bytes
    // while native writes and CM acknowledgement are pending.
    let baseline = match snapshot_capture::CapturedSnapshot::capture(&lease, fs) {
        Ok(image) => image,
        Err(status) => {
            return Err(stall_before_commit(slot, lease, token, proof, prepared, None, status));
        }
    };
    let mut staged = match nt_fs::FileSystem::from_volume_snapshot(baseline.as_slice()) {
        Ok(fs) => fs,
        Err(_) => {
            return Err(stall_before_commit(slot, lease, token, proof, prepared, None,
                nt_fs::STATUS_DATA_ERROR));
        }
    };
    drop(baseline);
    if let Err(status) = stage_prepared_checkpoint(&mut staged, &prepared) {
        return Err(stall_before_commit(slot, lease, token, proof, prepared, None, status));
    }
    SNAPSHOT_PUBLICATION.begin_fold_capture();
    let image = match snapshot_capture::CapturedSnapshot::capture(&lease, &staged) {
        Ok(image) => image,
        Err(status) => {
            return Err(stall_before_commit(slot, lease, token, proof, prepared, None, status));
        }
    };
    let bytes = image.as_slice().len();
    let mut commit = match AsyncSnapshotCommit::new_from_rechecked_pair(
        image, fold_manifest(manifest), proof) {
        Ok(commit) => commit,
        Err((error, image, proof)) => {
            return Err(stall_before_commit(slot, lease, token, proof, prepared, Some(image),
                snapshot_store_error_status(error)));
        }
    };
    commit.set_max_batch_sectors(crate::driver_launch::native_storage_transfer_sectors())
        .expect("a fresh snapshot commit has no request in flight");
    *slot = Some(Work::Active(Active { id, started_ticks, start_after_print,
        trace, write_sectors: 0,
        prepared, lease, token, old_pair: None, manifest, bytes,
        cursor: Some(Cursor::First(commit)), entered: false, failed: false }));
    Ok(())
}

/// Only a timer service boundary calls this after a no-effect refusal. An ordinary native I/O
/// pump sees AdmissionPending as inert and cannot mint a fresh header owner on every pass.
unsafe fn retry_pending_admission() -> Result<bool, u32> {
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::AdmissionPending { retry_after_100ns, .. }) = slot.as_ref() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if crate::monotonic_time_100ns() < *retry_after_100ns {
        return Err(snapshot_storage::BUSY);
    }
    let Some(Work::AdmissionPending { prepared, manifest, mount, .. }) = slot.take()
        else { unreachable!() };
    let lease = match snapshot_storage::acquire() {
        Ok(lease) => lease,
        Err(status) if status == snapshot_storage::BUSY => {
            *slot = Some(Work::AdmissionPending { prepared, manifest, mount,
                retry_after_100ns: crate::monotonic_time_100ns()
                    .saturating_add(ADMISSION_RETRY_100NS), last_status: status });
            return Err(snapshot_storage::BUSY);
        }
        Err(status) => {
            *slot = Some(Work::Stalled(StalledState::Admission {
                _lease: None, _prepared: prepared, _mount: mount, _manifest: manifest,
            }));
            return Err(block(status));
        }
    };
    if *lease.identity() != mount {
        *slot = Some(Work::Stalled(StalledState::Admission {
            _lease: Some(lease), _prepared: prepared, _mount: mount, _manifest: manifest,
        }));
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    let observed = match snapshot_storage::cached_wal_manifest(&lease) {
        Ok(observed) => observed,
        Err(status) => {
            *slot = Some(Work::Stalled(StalledState::Admission {
                _lease: Some(lease), _prepared: prepared, _mount: mount, _manifest: manifest,
            }));
            return Err(block(status));
        }
    };
    // Non-SYSTEM hive records may have extended this same verified WAL while the reserve was
    // released. CM's retained preparation excludes new SYSTEM mutations; accept only a
    // monotonically extended suffix in the same incarnation and replay base.
    if observed.incarnation != manifest.incarnation
        || observed.base_serial != manifest.base_serial
        || observed.high_water_serial < manifest.high_water_serial
        || observed.high_water_end_lba < manifest.high_water_end_lba
        || (observed.high_water_serial == manifest.high_water_serial
            && observed.high_water_end_lba != manifest.high_water_end_lba)
    {
        *slot = Some(Work::Stalled(StalledState::Admission {
            _lease: Some(lease), _prepared: prepared, _mount: mount, _manifest: manifest,
        }));
        return Err(block(nt_fs::STATUS_DATA_ERROR));
    }
    Err(begin_recheck_with_prepared(lease, prepared, observed, mount))
}

unsafe fn begin_recheck_with_prepared(
    lease: snapshot_storage::Lease,
    prepared: Option<nt_config_client::PreparedSystemHiveCheckpoint>,
    manifest: nt_fs::WalSnapshotManifest,
    mount: SectionMountId,
) -> u32 {
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let id = match snapshot_storage::begin_wal_continuation_recheck_returning_lease(lease) {
        Ok(id) => id,
        Err((status, lease)) if status == snapshot_storage::BUSY
            || status == nt_fs::STATUS_INSUFFICIENT_RESOURCES =>
        {
            drop(lease);
            *slot = Some(Work::AdmissionPending { prepared, manifest, mount,
                retry_after_100ns: crate::monotonic_time_100ns()
                    .saturating_add(ADMISSION_RETRY_100NS), last_status: status });
            return snapshot_storage::BUSY;
        }
        Err((status, lease)) => {
            *slot = Some(Work::Stalled(StalledState::Admission {
                _lease: Some(lease), _prepared: prepared, _mount: mount, _manifest: manifest,
            }));
            return block(status);
        }
    };
    let started_ticks = crate::disk_census_ticks();
    let trace = reserve_trace();
    *slot = Some(Work::Rechecking {
        id, prepared, manifest, mount, started_ticks, start_after_print: false, trace,
    });
    trace_started(id, manifest, trace);
    if let Some(Work::Rechecking { id: retained_id, started_ticks,
        start_after_print, .. }) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
    {
        if *retained_id == id {
            *started_ticks = crate::disk_census_ticks();
            *start_after_print = true;
        }
    }
    mark_runtime_dirty();
    snapshot_storage::BUSY
}

pub(super) unsafe fn fold_system_wal_native() -> Result<bool, u32> {
    let _durable = crate::allocator::enter_durable();
    if (*core::ptr::addr_of!(EXEC_WRITABLE_FS)).is_none()
        || legacy_snapshot_writes_allowed()
        || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_DEVICE_NOT_READY);
    }
    if matches!((&*core::ptr::addr_of!(WORK)).as_ref(),
        Some(Work::AdmissionPending { .. })) {
        return retry_pending_admission();
    }
    if (&*core::ptr::addr_of!(WORK)).is_some() {
        advance_recheck()?;
        return Err(snapshot_storage::BUSY);
    }
    let lease = snapshot_storage::acquire()?;
    let manifest = snapshot_storage::cached_wal_manifest(&lease).map_err(|status| {
        block(report_fold_failure(b"cached-manifest-native", status))
    })?;
    let prepared = if SYSTEM_WAL_FOLD_REQUIRED.load(Ordering::Acquire) {
        Some(crate::config_manager_prepare_system_hive_checkpoint_for_restored_wal()
            .map_err(|status| status as u32)?)
    } else {
        crate::config_manager_prepare_system_hive_checkpoint()
            .map_err(|status| status as u32)?
    };
    if prepared.is_none() && manifest.base_serial == manifest.high_water_serial {
        return Ok(false);
    }
    let mount = *lease.identity();
    Err(begin_recheck_with_prepared(lease, prepared, manifest, mount))
}

/// The header recheck this fold is waiting on, while it is rechecking.
pub(crate) unsafe fn recheck_id() -> Option<u64> {
    match (&*core::ptr::addr_of!(WORK)).as_ref() {
        Some(Work::Rechecking { id, .. }) => Some(*id),
        _ => None,
    }
}

/// This fold holds the snapshot reserve (rechecking or active).
pub(crate) unsafe fn holds_reserve() -> bool {
    matches!((&*core::ptr::addr_of!(WORK)).as_ref(),
        Some(Work::Rechecking { .. } | Work::Active(_)))
}

/// This fold holds the snapshot reserve and has work only the outer owner may claim.
pub(crate) unsafe fn outer_io_queued() -> bool {
    match (&*core::ptr::addr_of!(WORK)).as_ref() {
        Some(Work::Rechecking { id, .. }) => snapshot_storage::header_outer_io_queued(*id),
        Some(Work::Active(active)) => !active.entered && !active.failed
            && active.cursor.as_ref().is_some_and(|cursor| {
                cursor.pending().is_none() && !cursor.is_done()
            }),
        Some(Work::AdmissionPending { .. } | Work::Stalled(_)) | None => false,
    }
}

pub(crate) unsafe fn claim_next() -> Option<native_snapshot_io::SnapshotClaim> {
    let _durable = crate::allocator::enter_durable();
    if advance_recheck().is_err() { return None; }
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return None; };
    if active.entered || active.failed { return None; }
    let request = match active.cursor.as_mut().expect("active fold cursor").enter_next() {
        Ok(Some(request)) => request,
        Ok(None) | Err(nt_fs::AsyncSnapshotCommitError::Outstanding) => return None,
        Err(_) => { active.failed = true; block(nt_fs::STATUS_DEVICE_NOT_READY); return None; }
    };
    let operation = match request.kind {
        AsyncSnapshotIoKind::Flush => nt_fs::BlockOperation::Flush,
        AsyncSnapshotIoKind::Read | AsyncSnapshotIoKind::Write => {
            let sectors = u32::try_from(request.bytes / 512).ok().filter(|count| {
                *count > 0 && *count as usize * 512 == request.bytes
                    && request.lba.checked_add(u64::from(*count))
                        .is_some_and(|end| end <= active.lease.sector_count())
            });
            let lba = sectors.and_then(|_| snapshot_storage::physical_lba(&active.lease, request.lba).ok());
            let (Some(sectors), Some(lba)) = (sectors, lba) else {
                active.failed = true; block(nt_fs::STATUS_INVALID_PARAMETER); return None;
            };
            if request.kind == AsyncSnapshotIoKind::Read {
                nt_fs::BlockOperation::Read { lba, sectors }
            } else { nt_fs::BlockOperation::Write { lba, sectors } }
        }
    };
    let mut input = Vec::new();
    let input_len = active.cursor.as_ref().expect("active fold cursor")
        .write_bytes(request).map(<[u8]>::len);
    if let Some(len) = input_len {
        if input.try_reserve_exact(len).is_err() {
            let _ = active.cursor.as_mut().expect("active fold cursor").release_unentered(request);
            return None;
        }
        let bytes = active.cursor.as_ref().expect("active fold cursor")
            .write_bytes(request).expect("checked fold write buffer");
        input.extend_from_slice(bytes);
    }
    Some(native_snapshot_io::SnapshotClaim::from_fold(*active.lease.identity(), operation,
        input, FoldTicket { id: active.id, request }))
}

pub(crate) unsafe fn mark_entered(ticket: &FoldTicket) -> Result<(), u32> {
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || active.entered || active.failed
        || active.cursor.as_ref().expect("active fold cursor").pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.entered = true;
    Ok(())
}

pub(crate) unsafe fn release_unentered(ticket: FoldTicket) -> Result<(), u32> {
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || active.entered || active.failed {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.cursor.as_mut().expect("active fold cursor").release_unentered(ticket.request)
        .map_err(|_| nt_fs::STATUS_INVALID_DEVICE_REQUEST)
}

pub(crate) unsafe fn refuse_unentered(ticket: FoldTicket, status: nt_status::NtStatus)
    -> Result<(), u32> {
    let Some(Work::Active(active)) = (&mut *core::ptr::addr_of_mut!(WORK)).as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || active.entered || active.failed {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.cursor.as_mut().expect("active fold cursor").lose(ticket.request);
    active.failed = true;
    block(status.0 as u32);
    Ok(())
}

pub(crate) unsafe fn complete(ticket: FoldTicket, result: Result<&[u8], nt_status::NtStatus>)
    -> Result<super::super::native_snapshot_io::SnapshotCompletion, u32> {
    use super::super::native_snapshot_io::SnapshotCompletion;
    let slot = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(Work::Active(active)) = slot.as_mut()
        else { return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST); };
    if active.id != ticket.id || !active.entered || active.failed
        || active.cursor.as_ref().expect("active fold cursor").pending() != Some(ticket.request) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let completed = match result {
        Ok(bytes) => unsafe { active.cursor.as_mut().expect("active fold cursor").complete(ticket.request, bytes) },
        Err(_) => Err(nt_fs::AsyncSnapshotCommitError::Store(nt_fs::SnapshotBlockStoreError::Io)),
    };
    if completed.is_err() {
        active.failed = true;
        return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DEVICE_NOT_READY)));
    }
    if ticket.request.kind == AsyncSnapshotIoKind::Write {
        let sector_size = active.lease.sector_size();
        active.write_sectors = active.write_sectors
            .saturating_add((ticket.request.bytes / sector_size) as u64);
    }
    active.entered = false;
    if !active.cursor.as_ref().expect("active fold cursor").is_done() { return Ok(SnapshotCompletion::Settled); }
    let Some(Work::Active(mut active)) = slot.take() else { unreachable!() };
    match active.cursor.take().expect("completed fold cursor") {
        Cursor::First(commit) => {
            // Every request above was completed by the native executor after terminal + ACK.
            let (image, generation, pair) = match unsafe { commit.finish_with_payload_and_paired_proof() } {
                Ok(parts) => parts,
                Err(commit) => {
                    active.cursor = Some(Cursor::First(commit));
                    active.failed = true;
                    *slot = Some(Work::Active(active));
                    return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DATA_ERROR)));
                }
            };
            if pair.anchor() != active.token.anchor() {
                return Ok(SnapshotCompletion::Failed(stall_second_admission(slot, active, image, pair,
                    nt_fs::STATUS_DATA_ERROR)));
            }
            WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(active.bytes as u64, Ordering::Relaxed);
            // First-pass terminal and strict ACK minted this pair under the same exclusive lease.
            let mut second = match unsafe { AsyncSnapshotCommit::new_from_verified_pair(
                active.lease.store(), image, fold_manifest(active.manifest),
                active.lease.sector_size(), active.lease.sector_count(), pair) } {
                Ok(second) => second,
                Err((error, image, pair)) => return Ok(SnapshotCompletion::Failed(stall_second_admission(
                    slot, active, image, pair, snapshot_store_error_status(error)))),
            };
            second.set_max_batch_sectors(crate::driver_launch::native_storage_transfer_sectors())
                .expect("a fresh snapshot commit has no request in flight");
            active.cursor = Some(Cursor::Second(second));
            *slot = Some(Work::Active(active));
        }
        Cursor::Second(commit) => {
            let (_image, generation, pair) = match unsafe { commit.finish_with_payload_and_paired_proof() } {
                Ok(parts) => parts,
                Err(commit) => {
                    active.cursor = Some(Cursor::Second(commit));
                    active.failed = true;
                    *slot = Some(Work::Active(active));
                    return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DATA_ERROR)));
                }
            };
            WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
            WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(active.bytes as u64, Ordering::Relaxed);
            if pair.anchor() != active.token.anchor() {
                active.old_pair = Some(pair);
                return Ok(SnapshotCompletion::Failed(stall(slot, active, nt_fs::STATUS_DATA_ERROR)));
            }
            active.old_pair = Some(pair);
            let (start, sectors) = match snapshot_storage::wal_bounds(&active.lease) {
                Ok(bounds) => bounds,
                Err(status) => return Ok(SnapshotCompletion::Failed(stall(slot, active, status))),
            };
            if needs_epoch_rollover(active.manifest.high_water_end_lba, sectors) {
                let Some(next) = active.manifest.incarnation.checked_add(1) else {
                    return Ok(SnapshotCompletion::Failed(stall(slot, active, nt_fs::STATUS_DATA_ERROR)));
                };
                let pair = active.old_pair.take().expect("second folded pair retained");
                let cursor = match AsyncWalEpochRollover::admit(active.lease.store(), pair,
                    start, sectors, next, active.lease.sector_size(), active.lease.sector_count())
                { Ok(cursor) => cursor,
                    Err((error, pair)) => {
                        active.old_pair = Some(pair);
                        return Ok(SnapshotCompletion::Failed(stall(slot, active, snapshot_store_error_status(error))));
                    }
                };
                active.cursor = Some(Cursor::Rollover(cursor));
                *slot = Some(Work::Active(active));
            } else {
                let pair = active.old_pair.take().expect("second folded pair retained");
                publish_ready(active, None, pair);
            }
        }
        Cursor::Rollover(cursor) => {
            let (next, pair) = match cursor.finish() {
                Ok(parts) => parts,
                Err(cursor) => {
                    active.cursor = Some(Cursor::Rollover(cursor));
                    active.failed = true;
                    *slot = Some(Work::Active(active));
                    return Ok(SnapshotCompletion::Failed(block(nt_fs::STATUS_DATA_ERROR)));
                }
            };
            publish_ready(active, Some(next), pair);
        }
    }
    Ok(SnapshotCompletion::Settled)
}

fn stall(slot: &mut Option<Work>, active: Active, status: u32) -> u32 {
    *slot = Some(Work::Stalled(StalledState::Active(active)));
    block(status)
}

fn stall_second_admission(
    slot: &mut Option<Work>, active: Active, image: snapshot_capture::CapturedSnapshot,
    pair: nt_fs::VerifiedPairedWalSnapshot, status: u32,
) -> u32 {
    *slot = Some(Work::Stalled(StalledState::SecondAdmission {
        _active: active, _image: image, _pair: pair,
    }));
    block(status)
}

unsafe fn publish_ready(active: Active,
    next: Option<nt_fs::RegistryWalContinuation>,
    pair: nt_fs::VerifiedPairedWalSnapshot,
) {
    let trace = active.trace;
    let (id, bytes, write_sectors, started_ticks, start_after_print, rollover) = (
        active.id, active.bytes as u64, active.write_sectors,
        active.started_ticks, active.start_after_print, u64::from(next.is_some()),
    );
    let old = if next.is_none() { Some(active.token) } else { None };
    *core::ptr::addr_of_mut!(FOLD_WORK) = Some(FoldWork {
        prepared: active.prepared, lease: active.lease,
        old_continuation: old, old_pair: active.old_pair,
        next_continuation: next, next_pair: Some(pair),
        publish_prepared_after_ack: true, phase: Phase::Acknowledging,
    });
    // The owner was installed before its begin receipt. A matching owner refreshed its clock
    // afterward; reentrant work retained the earlier safe clock. The end is after FOLD_WORK
    // owns the CM ACK and before this completion receipt prints.
    let elapsed_ticks = crate::disk_census_ticks().wrapping_sub(started_ticks);
    if trace {
        // Header recheck, private FS capture, CM staging, native writes, both paired proofs,
        // and an optional rollover are complete. FOLD_WORK still retains the CM ACK.
        print_str(b"[writable-fs-fold-measure] pre-ack-finished id/bytes/write-sectors/pre-ack-elapsed-tsc/start-after-begin-print/rollover=");
        for value in [id, bytes, write_sectors, elapsed_ticks,
            u64::from(start_after_print), rollover] {
            print_str(b"/"); print_u64(value);
        }
        print_str(b"\n");
    }
}
