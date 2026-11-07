//! One top-level native block continuation for mounted FAT and snapshot I/O.
//!
//! Mounted backends and snapshot journals own their logical cursors. This owner retains a
//! single physical block ticket and canonical SCSI packet until the provider's exact terminal
//! and acknowledgement. It never enters a completion pump from backend dispatch.

use super::*;
use nt_io_manager::{
    detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest},
    scsi_block_command::ScsiBlockCommand,
    scsi_srb_transport::ScsiParameters,
    scsi_srb_wire::decode_scsi_completion,
    IoParameters, StackFlags,
};
use nt_hosted_runtime::{drain_cached_claims, CacheClaimStep};

const CACHE_CLAIMS_PER_TURN: usize = 32;
const MOUNTED_RETRY_DELAY_100NS: u64 = 100_000;
static WAKE: nt_time::CoalescedRetryWake = nt_time::CoalescedRetryWake::new();
static WAKE_LATENCY: nt_time::RetainedWakeLatency = nt_time::RetainedWakeLatency::new();
static WAKE_UNSAMPLED: AtomicU64 = AtomicU64::new(0);

// Native mounted SCSI traffic is distinct from the direct boot AHCI census. Completion is
// counted only after the exact IRP terminal (and, for pending IRPs, acknowledgement).
static NATIVE_FAT_CENSUS: nt_ahci::CommandCensus = nt_ahci::CommandCensus::new();
static NATIVE_SNAPSHOT_CENSUS: nt_ahci::CommandCensus = nt_ahci::CommandCensus::new();
// Count only installed-file READ claims accepted by the physical route. Metadata and snapshot
// commands are excluded, so this shows whether the mounted READ sector ceiling binds in vivo.
struct InstalledReadShapeCensus {
    zero: AtomicU64,
    one: AtomicU64,
    two: AtomicU64,
    three: AtomicU64,
    four: AtomicU64,
    more: AtomicU64,
}

impl InstalledReadShapeCensus {
    const fn new() -> Self {
        Self { zero: AtomicU64::new(0), one: AtomicU64::new(0), two: AtomicU64::new(0),
            three: AtomicU64::new(0), four: AtomicU64::new(0),
            more: AtomicU64::new(0) }
    }

    fn record(&self, sectors: u32) {
        let bucket = match sectors {
            0 => &self.zero,
            1 => &self.one,
            2 => &self.two,
            3 => &self.three,
            4 => &self.four,
            _ => &self.more,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    fn print(&self) {
        print_str(b"[census] native-installed-read entered-sectors-0/1/2/3/4/gt4=");
        for (index, bucket) in [&self.zero, &self.one, &self.two, &self.three, &self.four, &self.more]
            .iter().enumerate()
        {
            if index != 0 { print_str(b"/"); }
            print_u64(bucket.load(Ordering::Relaxed));
        }
        print_str(b"\n");
    }
}

static NATIVE_INSTALLED_READ_SHAPE: InstalledReadShapeCensus = InstalledReadShapeCensus::new();
// The census can run inside a nested completion pump, so it observes only atomics and never
// borrows the mutable retained Pending owner.
static NATIVE_PENDING_IRP: AtomicU64 = AtomicU64::new(0);
static NATIVE_PENDING_STARTED: AtomicU64 = AtomicU64::new(0);
static NATIVE_PENDING_BYTES: AtomicU64 = AtomicU64::new(0);
static NATIVE_PENDING_SOURCE: AtomicU64 = AtomicU64::new(0);

// Measurement only: authenticated metadata bytes are copied after terminal/ACK, but every
// request still enters the physical route. This measures whether repeat lookups justify a
// read-through cache without changing the mounted File or SCSI ownership contract.
type MetadataKey = (u64, nt_pnp_context::native_storage_handoff::StorageHandoffKey);
type MetadataDisk = (HostedDomainIdentity, nt_io_manager::DeviceId, u64);
static mut METADATA_SHADOW: nt_fs::InstalledMetadataSectorCache<MetadataKey, 512> =
    nt_fs::InstalledMetadataSectorCache::new();
static mut METADATA_SHADOW_ROUTE: Option<MetadataKey> = None;
// The first accepted native route owns this for the rest of its mount. A relation refresh may
// invalidate the shadow, but cannot erase an earlier possible write or uncertain effect.
static mut METADATA_FENCE: Option<nt_fs::InstalledMetadataReadThroughFence<MetadataDisk, MetadataKey>> = None;
static METADATA_FENCE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static METADATA_FENCE_POISONS: AtomicU64 = AtomicU64::new(0);
static METADATA_READ_THROUGH_HITS: AtomicU64 = AtomicU64::new(0);
static METADATA_EXTRA_HITS_IN_TURN: AtomicU64 = AtomicU64::new(0);
// Observation only: sample the first two unclassified shapes per opcode even after the
// irreversible fence has poisoned. This may expose later read-only classification gaps.
static UNCLASSIFIED_SRB_TRACES: [AtomicU64; 256] =
    [const { AtomicU64::new(0) }; 256];

struct MetadataShadowCensus {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl MetadataShadowCensus {
    const fn new() -> Self {
        Self { hits: AtomicU64::new(0), misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0) }
    }

    fn print(&self, kind: &[u8]) {
        print_str(b"[census] native-metadata-shadow kind=");
        print_str(kind);
        print_str(b" hits/misses/evictions=");
        print_u64(self.hits.load(Ordering::Relaxed));
        print_str(b"/");
        print_u64(self.misses.load(Ordering::Relaxed));
        print_str(b"/");
        print_u64(self.evictions.load(Ordering::Relaxed));
        print_str(b"\n");
    }
}

static METADATA_CREATE_SHADOW: MetadataShadowCensus = MetadataShadowCensus::new();
static METADATA_DIRECTORY_SHADOW: MetadataShadowCensus = MetadataShadowCensus::new();

/// Diagnostic timings only. These atomics can be sampled from a nested completion pump without
/// borrowing the retained physical command or changing its admission and ACK ownership.
struct PhaseCensus {
    commands: AtomicU64,
    ticks: AtomicU64,
    max_ticks: AtomicU64,
}

impl PhaseCensus {
    const fn new() -> Self {
        Self { commands: AtomicU64::new(0), ticks: AtomicU64::new(0),
            max_ticks: AtomicU64::new(0) }
    }

    fn record(&self, started: u64, finished: u64) {
        let elapsed = finished.wrapping_sub(started);
        self.commands.fetch_add(1, Ordering::Relaxed);
        self.ticks.fetch_add(elapsed, Ordering::Relaxed);
        self.max_ticks.fetch_max(elapsed, Ordering::Relaxed);
    }

    fn print(&self, phase: &[u8]) {
        print_str(b"[census] native-block-phase ");
        print_str(phase);
        print_str(b"=");
        print_u64(self.commands.load(Ordering::Relaxed));
        print_str(b"cmd/");
        print_u64(self.ticks.load(Ordering::Relaxed) / 1_000_000);
        print_str(b"total-Mtick/");
        print_u64(self.max_ticks.load(Ordering::Relaxed) / 1_000_000);
        print_str(b"max-Mtick\n");
    }
}

static NATIVE_PREP_PHASE: PhaseCensus = PhaseCensus::new();
static NATIVE_DISPATCH_TERMINAL_PHASE: PhaseCensus = PhaseCensus::new();
static NATIVE_DISPATCH_CALL_PHASE: PhaseCensus = PhaseCensus::new();
static NATIVE_DISPATCH_RETURN_TERMINAL_PHASE: PhaseCensus = PhaseCensus::new();
static NATIVE_TERMINAL_SETTLE_PHASE: PhaseCensus = PhaseCensus::new();
static NATIVE_CLAIM_SEARCH_PHASE: PhaseCensus = PhaseCensus::new();
// This is an upper bound on idle time: there may be no claimable work between two commands.
static NATIVE_INTER_COMMAND_PHASE: PhaseCensus = PhaseCensus::new();
static NATIVE_LAST_SETTLED_TICKS: AtomicU64 = AtomicU64::new(0);

// Counts service admission without conflating an empty backend queue with physical latency.
static NATIVE_SERVICE_GUARD_BUSY: AtomicU64 = AtomicU64::new(0);
static NATIVE_SERVICE_PENDING_WAIT: AtomicU64 = AtomicU64::new(0);
static NATIVE_SERVICE_CLAIM_HIT_FRESH: AtomicU64 = AtomicU64::new(0);
static NATIVE_SERVICE_CLAIM_HIT_AFTER_SETTLE: AtomicU64 = AtomicU64::new(0);
static NATIVE_SERVICE_CLAIM_MISS_FRESH: AtomicU64 = AtomicU64::new(0);
static NATIVE_SERVICE_CLAIM_MISS_AFTER_SETTLE: AtomicU64 = AtomicU64::new(0);

fn record_inter_command_gap(claim_started_ticks: u64) {
    let last_settled = NATIVE_LAST_SETTLED_TICKS.swap(0, Ordering::Relaxed);
    if last_settled != 0 {
        NATIVE_INTER_COMMAND_PHASE.record(last_settled, claim_started_ticks);
    }
}

pub(super) fn print_census() {
    let w = WAKE_LATENCY.snapshot();
    print_str(b"[census] mounted-wake samples/empty/nested/unknown/unsampled=");
    for (i, n) in [w.samples, w.empty_epochs, w.coalesced_publications,
        w.unknown_epochs, WAKE_UNSAMPLED.load(Ordering::Relaxed)].iter().enumerate() {
        if i != 0 { print_str(b"/"); } print_u64(*n);
    }
    print_str(b" pub/follow/due/service-total-ms=");
    for (i, n) in [w.published_total_100ns, w.follow_on_total_100ns,
        w.due_total_100ns, w.service_total_100ns].iter().enumerate() {
        if i != 0 { print_str(b"/"); } print_u64(*n / 10_000);
    }
    print_str(b" pub/follow-n="); print_u64(w.samples - w.follow_on_samples);
    print_str(b"/"); print_u64(w.follow_on_samples);
    for (name, bins, count) in [(b" pub".as_slice(), &w.published_buckets,
        w.samples - w.follow_on_samples), (b" follow".as_slice(), &w.follow_on_buckets,
        w.follow_on_samples)] {
        print_str(name); print_str(b"-p50/p95-bucket-upper-ms=");
        for p in [50, 95] {
            if p == 95 { print_str(b"/"); }
            match nt_time::WakeLatencySnapshot::percentile_bound(bins, count, p) {
                Some(u64::MAX) => print_str(b"50+"),
                Some(bound) => print_u64(bound / 10_000),
                None => print_str(b"none"),
            }
        }
    }
    print_str(b"\n");
    crate::mounted_volume::print_mounted_create_census();
    // Census can run in a nested completion pump: only observe atomics here.
    METADATA_CREATE_SHADOW.print(b"create");
    METADATA_DIRECTORY_SHADOW.print(b"directory");
    print_str(b"[census] native-metadata-fence initialized/poisoned=");
    print_u64(u64::from(METADATA_FENCE_INITIALIZED.load(Ordering::Acquire)));
    print_str(b"/");
    print_u64(METADATA_FENCE_POISONS.load(Ordering::Relaxed));
    print_str(b"\n");
    print_str(b"[census] native-metadata-read-through hits=");
    print_u64(METADATA_READ_THROUGH_HITS.load(Ordering::Relaxed));
    print_str(b"\n");
    print_str(b"[census] native-metadata-cache-drain extra-hits=");
    print_u64(METADATA_EXTRA_HITS_IN_TURN.load(Ordering::Relaxed));
    print_str(b"\n");
    let published = native_disk_relation::native_storage_route();
    let retained = native_disk_relation::retained_native_storage_recheck_route();
    print_str(b"[mounted-route-census] phase=");
    print_str(if published.is_some() { b"published".as_slice() }
        else if retained.is_some() { b"retained-recheck-only".as_slice() }
        else { b"absent".as_slice() });
    if let Some(route) = published.or(retained) {
        print_str(b" mount=");
        print_u64(route.mount.value());
        print_str(b" driver=");
        print_u64(route.driver_id.raw());
        print_str(b" generation=");
        print_u64(route.key.relation.generation);
    }
    print_str(b" recheck-id=");
    print_u64(unsafe { crate::driver_launch::native_storage_relation_recheck_id() }.unwrap_or(0));
    print_str(b"\n");
    for (source, census) in [
        (b"fat".as_slice(), &NATIVE_FAT_CENSUS),
        (b"snapshot".as_slice(), &NATIVE_SNAPSHOT_CENSUS),
    ] {
        print_str(b"[census] native-block source=");
        print_str(source);
        for (label, operation) in [
            (b" read=".as_slice(), nt_ahci::IoOperation::Read),
            (b" write=".as_slice(), nt_ahci::IoOperation::Write),
            (b" flush=".as_slice(), nt_ahci::IoOperation::Barrier),
        ] {
            let sample = census.snapshot(operation);
            print_str(label);
            print_u64(sample.commands);
            print_str(b"settled/");
            print_u64(sample.sectors);
            print_str(b"requested-sec/");
            print_u64(sample.ticks / 1_000_000);
            print_str(b"Mtick/");
            print_u64(sample.failures);
            print_str(b"fail");
        }
        print_str(b"\n");
    }
    NATIVE_INSTALLED_READ_SHAPE.print();
    NATIVE_PREP_PHASE.print(b"claim-to-dispatch");
    NATIVE_DISPATCH_TERMINAL_PHASE.print(b"dispatch-to-terminal");
    NATIVE_DISPATCH_CALL_PHASE.print(b"dispatch-call");
    NATIVE_DISPATCH_RETURN_TERMINAL_PHASE.print(b"dispatch-return-to-terminal");
    NATIVE_TERMINAL_SETTLE_PHASE.print(b"terminal-to-settle");
    print_str(b"[census] native-block-phase published-claim-search=");
    print_u64(NATIVE_CLAIM_SEARCH_PHASE.commands.load(Ordering::Relaxed));
    print_str(b"attempt/");
    print_u64(NATIVE_CLAIM_SEARCH_PHASE.ticks.load(Ordering::Relaxed) / 1_000_000);
    print_str(b"total-Mtick/");
    print_u64(NATIVE_CLAIM_SEARCH_PHASE.max_ticks.load(Ordering::Relaxed) / 1_000_000);
    print_str(b"max-Mtick\n");
    NATIVE_INTER_COMMAND_PHASE.print(b"between-commands-upper-bound");
    print_str(b"[census] native-block-service guard-busy/pending-wait/");
    print_str(b"claim-hit-fresh/claim-hit-after-settle/claim-miss-fresh/claim-miss-after-settle=");
    for (index, count) in [&NATIVE_SERVICE_GUARD_BUSY, &NATIVE_SERVICE_PENDING_WAIT,
        &NATIVE_SERVICE_CLAIM_HIT_FRESH, &NATIVE_SERVICE_CLAIM_HIT_AFTER_SETTLE,
        &NATIVE_SERVICE_CLAIM_MISS_FRESH, &NATIVE_SERVICE_CLAIM_MISS_AFTER_SETTLE]
        .iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(count.load(Ordering::Relaxed));
    }
    print_str(b"\n");
    let pending_irp = NATIVE_PENDING_IRP.load(Ordering::Acquire);
    if pending_irp != 0 {
        print_str(b"[census] native-block pending irp=");
        print_u64(pending_irp);
        print_str(b" source=");
        print_str(if NATIVE_PENDING_SOURCE.load(Ordering::Relaxed) == 0 {
            b"fat".as_slice()
        } else {
            b"snapshot".as_slice()
        });
        print_str(b" bytes=");
        print_u64(NATIVE_PENDING_BYTES.load(Ordering::Relaxed));
        print_str(b" outstanding-Mtick=");
        print_u64(crate::disk_census_ticks().wrapping_sub(
            NATIVE_PENDING_STARTED.load(Ordering::Relaxed)) / 1_000_000);
        print_str(b"\n");
    }
}

#[derive(Clone, Copy)]
enum SectorClaim {
    Create(crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim),
    Overlay(nt_fs::OverlaySectorClaim),
    Read(crate::mounted_volume_backend::mounted_installed_read::ReadSectorClaim),
    Directory(crate::mounted_volume_backend::mounted_directory_lookup::DirectorySectorClaim),
}

impl SectorClaim {
    fn mount(self) -> u64 {
        match self {
            Self::Create(c) => c.mount,
            Self::Overlay(c) => c.mount,
            Self::Read(c) => c.mount,
            Self::Directory(c) => c.mount,
        }
    }

    fn sector(self) -> u32 {
        match self {
            Self::Create(c) => c.request.sector,
            Self::Overlay(c) => match c.request {
                nt_fs::OverlaySectorRequest::Parent(request) => request.sector,
                nt_fs::OverlaySectorRequest::Contents(request) => request.sector,
            },
            Self::Read(c) => c.request.sector,
            Self::Directory(c) => c.request.sector,
        }
    }

    fn release_unentered(self) {
        match self {
            Self::Create(c) => crate::mounted_volume::release_unentered_mounted_create_sector(c)
                .expect("unentered CREATE sector claim lost"),
            Self::Overlay(c) => crate::mounted_volume::release_unentered_mounted_overlay_sector(c)
                .expect("unentered overlay sector claim lost"),
            Self::Read(c) => crate::mounted_volume::release_unentered_mounted_read_sector(c)
                .expect("unentered READ sector claim lost"),
            Self::Directory(c) => crate::mounted_volume::release_unentered_mounted_directory_sector(c)
                .expect("unentered DIRECTORY sector claim lost"),
        }
    }

    fn complete(self, bytes: Result<&[u8], nt_fs::FatPathError>) {
        match self {
            Self::Create(c) => {
                let sector = bytes.and_then(|bytes| <&[u8; 512]>::try_from(bytes)
                    .map_err(|_| nt_fs::FatPathError::Corrupt));
                crate::mounted_volume::complete_mounted_create_sector(c, sector)
                    .expect("entered CREATE sector claim lost");
            }
            Self::Overlay(c) => {
                let sector = bytes.and_then(|bytes| <&[u8; 512]>::try_from(bytes)
                    .map_err(|_| nt_fs::FatPathError::Corrupt));
                crate::mounted_volume::complete_mounted_overlay_sector(c, sector)
                    .expect("entered overlay sector claim lost");
            }
            Self::Read(c) => {
                crate::mounted_volume::complete_mounted_read_sectors(c, bytes)
                    .expect("entered READ sector claim lost");
            }
            Self::Directory(c) => {
                let sector = bytes.and_then(|bytes| <&[u8; 512]>::try_from(bytes)
                    .map_err(|_| nt_fs::FatPathError::Corrupt));
                crate::mounted_volume::complete_mounted_directory_sector(c, sector)
                    .expect("entered DIRECTORY sector claim lost");
            }
        }
    }

    fn complete_physical(self, bytes: Result<&[u8], nt_fs::FatPathError>) {
        match self {
            Self::Create(c) => {
                let sector = bytes.and_then(|bytes| <&[u8; 512]>::try_from(bytes)
                    .map_err(|_| nt_fs::FatPathError::Corrupt));
                crate::mounted_volume::complete_physical_mounted_create_sector(c, sector)
                    .expect("settled physical CREATE sector claim lost");
            }
            claim => claim.complete(bytes),
        }
    }
}

enum WorkClaim {
    Sector(SectorClaim),
    Snapshot(crate::writable_fs::native_snapshot_io::SnapshotClaim),
}

fn record_entered_installed_read(claim: &WorkClaim) {
    if let WorkClaim::Sector(SectorClaim::Read(read)) = claim {
        NATIVE_INSTALLED_READ_SHAPE.record(read.sectors);
    }
}

impl WorkClaim {
    fn mount(&self) -> u64 {
        match self {
            Self::Sector(claim) => claim.mount(),
            Self::Snapshot(claim) => claim.mount.value(),
        }
    }

    fn source(&self) -> nt_fs::BlockSource {
        match self {
            Self::Sector(_) => nt_fs::BlockSource::Fat,
            Self::Snapshot(_) => nt_fs::BlockSource::Snapshot,
        }
    }

    fn operation(&self) -> Option<nt_fs::BlockOperation> {
        match self {
            Self::Sector(SectorClaim::Read(claim)) => {
                let fs = unsafe { crate::fs_loader::exec_fs()? };
                claim.block_read_operation(fs.volume_start_lba)
            }
            Self::Sector(claim) => {
                let fs = unsafe { crate::fs_loader::exec_fs()? };
                let lba = nt_fs::checked_partition_lba(fs.volume_start_lba, claim.sector())?;
                Some(nt_fs::BlockOperation::Read { lba, sectors: 1 })
            }
            Self::Snapshot(claim) => Some(claim.operation),
        }
    }

    fn mark_entered(&self) {
        if let Self::Snapshot(claim) = self {
            unsafe { crate::writable_fs::native_snapshot_io::mark_entered_native_snapshot_io(claim) }
                .expect("entered snapshot claim lost");
        }
    }

    fn release_unentered(self) {
        match self {
            Self::Sector(claim) => claim.release_unentered(),
            Self::Snapshot(claim) => unsafe {
                crate::writable_fs::native_snapshot_io::release_unentered_native_snapshot_io(claim)
            }.expect("unentered snapshot claim lost"),
        }
    }

    fn refuse_unentered(self, status: nt_status::NtStatus) {
        match self {
            Self::Sector(claim) => claim.complete(Err(nt_fs::FatPathError::Corrupt)),
            Self::Snapshot(claim) => unsafe {
                crate::writable_fs::native_snapshot_io::refuse_unentered_native_snapshot_io(claim, status)
            }.expect("refused unentered snapshot claim lost"),
        }
    }

    fn complete(self, result: Result<&[u8], nt_status::NtStatus>) {
        match self {
            Self::Sector(claim) => claim.complete(result.map_err(|_| nt_fs::FatPathError::Corrupt)),
            Self::Snapshot(claim) => {
                use crate::writable_fs::native_snapshot_io::SnapshotCompletion;
                let owner_kind = claim.owner_kind();
                let provider_status = result.err().map(|status| status.raw() as u32);
                match unsafe {
                    crate::writable_fs::native_snapshot_io::complete_native_snapshot_io(claim, result)
                } {
                    Ok(SnapshotCompletion::Settled) => {},
                    Ok(SnapshotCompletion::Failed(status)) => {
                        print_str(b"[native-snapshot-terminal] owner=");
                        print_str(owner_kind);
                        print_str(b" provider-status=0x");
                        print_hex64(provider_status.unwrap_or(0) as u64);
                        print_str(b" owner-status=0x");
                        print_hex64(status as u64);
                        print_str(b"\n");
                    }
                    Err(_) => panic!("acknowledged snapshot owner identity lost"),
                }
            }
        }
    }

    fn complete_physical(self, result: Result<&[u8], nt_status::NtStatus>) {
        match self {
            Self::Sector(claim) => claim.complete_physical(result.map_err(|_| nt_fs::FatPathError::Corrupt)),
            claim => claim.complete(result),
        }
    }

    fn complete_cached(self, bytes: &[u8; 512]) {
        match self {
            Self::Sector(SectorClaim::Create(claim)) => {
                crate::mounted_volume::complete_cached_mounted_create_sector(claim, bytes)
                    .expect("copied exact CREATE sector claim lost");
            }
            Self::Sector(SectorClaim::Directory(claim)) => {
                crate::mounted_volume::complete_mounted_directory_sector(claim, Ok(bytes))
                    .expect("copied exact DIRECTORY sector claim lost");
            }
            Self::Sector(SectorClaim::Overlay(_) | SectorClaim::Read(_))
            | Self::Snapshot(_) => unreachable!("only metadata claims can use copied sectors"),
        }
    }

    fn write_input(&self) -> Option<&[u8]> {
        match self {
            Self::Snapshot(claim) => Some(&claim.input),
            Self::Sector(_) => None,
        }
    }
}

fn metadata_sector(claim: &WorkClaim) -> Option<(u32, &'static MetadataShadowCensus)> {
    match claim {
        WorkClaim::Sector(SectorClaim::Create(claim)) =>
            Some((claim.request.sector, &METADATA_CREATE_SHADOW)),
        WorkClaim::Sector(SectorClaim::Directory(claim)) =>
            Some((claim.request.sector, &METADATA_DIRECTORY_SHADOW)),
        WorkClaim::Sector(SectorClaim::Overlay(_) | SectorClaim::Read(_))
        | WorkClaim::Snapshot(_) => None,
    }
}

unsafe fn metadata_shadow_for(route: native_disk_relation::NativeStorageRoute)
    -> &'static mut nt_fs::InstalledMetadataSectorCache<MetadataKey, 512>
{
    let key = (route.mount.value(), route.key);
    let cache = &mut *core::ptr::addr_of_mut!(METADATA_SHADOW);
    let active = &mut *core::ptr::addr_of_mut!(METADATA_SHADOW_ROUTE);
    if *active != Some(key) {
        cache.invalidate();
        *active = Some(key);
    }
    cache
}

fn metadata_disk(route: nt_io_manager::scsi_srb_transport::ScsiSrbRoute) -> MetadataDisk {
    (route.provider, route.pdo, route.provider_pdo)
}

unsafe fn metadata_fence_for(route: native_disk_relation::NativeStorageRoute)
    -> Option<&'static nt_fs::InstalledMetadataReadThroughFence<MetadataDisk, MetadataKey>>
{
    let slot = &mut *core::ptr::addr_of_mut!(METADATA_FENCE);
    if slot.is_none() {
        if crate::fs_loader::exec_fs_mount_identity() != Some(route.mount) { return None; }
        let fat = crate::fs_loader::exec_fs()?;
        let installed = nt_fs::PhysicalSectorRange::new(
            fat.volume_start_lba, u64::from(fat.total_sectors))?;
        let reserve = crate::writable_fs::snapshot_storage::published_physical_range(route.mount)
            .and_then(|(start, sectors)| nt_fs::PhysicalSectorRange::new(start, sectors));
        *slot = nt_fs::InstalledMetadataReadThroughFence::new(
            metadata_disk(route.scsi), (route.mount.value(), route.key), installed, reserve);
        METADATA_FENCE_INITIALIZED.store(slot.is_some(), Ordering::Release);
    }
    slot.as_ref()
}

fn print_srb_effect_shape(srb: &[u8]) {
    print_str(b" srb cdb-len/flags/transfer/cdb1/cdb2/cdb3/cdb4/cdb5=");
    print_u64(u64::from(srb.get(0x0a).copied().unwrap_or(0)));
    print_str(b"/");
    print_u64(srb.get(0x0c..0x10)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes).unwrap_or(0) as u64);
    print_str(b"/");
    print_u64(srb.get(0x10..0x14)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes).unwrap_or(0) as u64);
    for offset in 0x49..=0x4d {
        print_str(b"/");
        print_u64(u64::from(srb.get(offset).copied().unwrap_or(0)));
    }
}

/// Called after the canonical File IRP has captured its physical stack, before provider entry.
/// The irreversible poison prevents a read from refilling the shadow while a write remains
/// pending or uncertain. This runs in Executive memory, where the metadata bytes are owned.
pub(super) unsafe fn before_external_scsi_effect(
    prepared: &nt_io_manager::detached_file_irp::PreparedExternalFileIrp,
    stack: &[(nt_io_manager::DeviceId, nt_io_manager::DriverId)],
) {
    let Some(route) = native_disk_relation::native_storage_route()
        .or_else(|| native_disk_relation::retained_native_storage_recheck_route()) else { return; };
    let targets_disk = stack.iter().any(|(device, _)| *device == route.scsi.pdo);
    let projection = prepared.projection();
    let effect = match &projection.parameters {
        IoParameters::Scsi(parameters) if metadata_disk(parameters.route) == metadata_disk(route.scsi) =>
            nt_fs::PossibleScsiEffect::from_legacy_srb(&parameters.srb),
        IoParameters::Read(_) if targets_disk => nt_fs::PossibleScsiEffect::ProvenReadOnly,
        IoParameters::DeviceControl(parameters) if targets_disk =>
            nt_fs::PossibleScsiEffect::from_disk_device_control(
                parameters.ioctl_code, parameters.input_len, parameters.output_len),
        _ if targets_disk => nt_fs::PossibleScsiEffect::PossiblyMutating,
        _ => return,
    };
    if matches!(effect, nt_fs::PossibleScsiEffect::PossiblyMutating) {
        if let IoParameters::Scsi(parameters) = &projection.parameters {
            if metadata_disk(parameters.route) == metadata_disk(route.scsi) {
                let opcode = parameters.srb.get(0x48).copied().unwrap_or(0);
                let occurrence = UNCLASSIFIED_SRB_TRACES[usize::from(opcode)]
                    .fetch_add(1, Ordering::Relaxed);
                if occurrence < 2 {
                    print_str(b"[native-metadata-unclassified-srb] occurrence/opcode/irp=");
                    print_u64(occurrence + 1);
                    print_str(b"/");
                    print_u64(u64::from(opcode));
                    print_str(b"/");
                    print_u64(prepared.irp_id().raw());
                    print_srb_effect_shape(&parameters.srb);
                    print_str(b"\n");
                }
            }
        }
    }
    let Some(fence) = metadata_fence_for(route) else { return; };
    let was_poisoned = fence.poisoned();
    fence.before_effect(&metadata_disk(route.scsi), effect);
    if !was_poisoned && fence.poisoned() {
        (&mut *core::ptr::addr_of_mut!(METADATA_SHADOW)).invalidate();
        METADATA_FENCE_POISONS.fetch_add(1, Ordering::Relaxed);
        print_str(b"[native-metadata-fence] poisoned before irp/major/code/input/output=");
        print_u64(prepared.irp_id().raw());
        print_str(b"/");
        print_u64(u64::from(projection.major));
        print_str(b"/");
        print_u64(match &projection.parameters {
            IoParameters::Scsi(parameters) => u64::from(parameters.srb.get(0x48).copied().unwrap_or(0)),
            IoParameters::DeviceControl(parameters)
            | IoParameters::InternalDeviceControl(parameters) => u64::from(parameters.ioctl_code),
            _ => 0,
        });
        print_str(b"/");
        print_u64(match &projection.parameters {
            IoParameters::DeviceControl(parameters)
            | IoParameters::InternalDeviceControl(parameters) => u64::from(parameters.input_len),
            _ => 0,
        });
        print_str(b"/");
        print_u64(match &projection.parameters {
            IoParameters::DeviceControl(parameters)
            | IoParameters::InternalDeviceControl(parameters) => u64::from(parameters.output_len),
            _ => 0,
        });
        if let IoParameters::Scsi(parameters) = &projection.parameters {
            print_srb_effect_shape(&parameters.srb);
        }
        print_str(b"\n");
    }
}

unsafe fn observe_metadata_shadow(
    route: native_disk_relation::NativeStorageRoute, claim: &WorkClaim,
) {
    let Some((sector, census)) = metadata_sector(claim) else { return; };
    let key = (route.mount.value(), route.key);
    let hit = metadata_shadow_for(route).lookup(key, sector).is_some();
    if hit { census.hits.fetch_add(1, Ordering::Relaxed); }
    else { census.misses.fetch_add(1, Ordering::Relaxed); }
}

unsafe fn publish_metadata_shadow(
    route: native_disk_relation::NativeStorageRoute, claim: &WorkClaim, bytes: &[u8],
) {
    let Some((sector, census)) = metadata_sector(claim) else { return; };
    let Ok(bytes) = <&[u8; 512]>::try_from(bytes) else { return; };
    let key = (route.mount.value(), route.key);
    if metadata_shadow_for(route).publish(key, sector, bytes) {
        census.evictions.fetch_add(1, Ordering::Relaxed);
    }
}

struct Terminal {
    status: nt_status::NtStatus,
    packet: Vec<u8>,
}

struct Pending {
    claim: WorkClaim,
    ticket: nt_fs::NativeBlockTicket,
    route: native_disk_relation::NativeStorageRoute,
    command: ScsiBlockCommand,
    irp: IrpId,
    requestor_tid: u64,
    terminal: Option<Terminal>,
    started_ticks: u64,
    dispatch_returned_ticks: u64,
    terminal_ticks: u64,
}

static mut PENDING: Option<Pending> = None;
static mut SNAPSHOT_FIRST: bool = false;

pub(super) fn pending_physical_irp() -> bool {
    unsafe { (&*core::ptr::addr_of!(PENDING)).as_ref()
        .is_some_and(|pending| pending.irp.raw() != 0) }
}

/// Atomic observation only: the receive boundary may run inside a completion pump.
pub(super) fn pending_physical_irp_id() -> u64 {
    NATIVE_PENDING_IRP.load(Ordering::Acquire)
}

pub(super) fn print_quiesce_snapshot() {
    print_str(b"[quiesce-native-block] mounted-create-outstanding=");
    print_u64(crate::mounted_volume::mounted_create_outstanding() as u64);
    print_str(b" mounted-read-outstanding=");
    print_u64(crate::mounted_volume::mounted_read_outstanding() as u64);
    print_str(b" physical-pending-irp=");
    let pending_irp = NATIVE_PENDING_IRP.load(Ordering::Acquire);
    print_u64(pending_irp);
    if pending_irp != 0 {
        print_str(b" source=");
        print_str(if NATIVE_PENDING_SOURCE.load(Ordering::Relaxed) == 0 {
            b"fat".as_slice()
        } else { b"snapshot".as_slice() });
        print_str(b" bytes=");
        print_u64(NATIVE_PENDING_BYTES.load(Ordering::Relaxed));
        print_str(b" outstanding-Mtick=");
        print_u64(crate::disk_census_ticks().wrapping_sub(
            NATIVE_PENDING_STARTED.load(Ordering::Relaxed)) / 1_000_000);
    }
    print_str(b"\n");
}

fn next_sector_claim() -> Option<WorkClaim> {
    crate::mounted_volume::claim_mounted_create_sector()
        .map(SectorClaim::Create)
        .or_else(|| crate::mounted_volume::claim_mounted_overlay_sector().map(SectorClaim::Overlay))
        .or_else(|| crate::mounted_volume::claim_mounted_read_sectors().map(SectorClaim::Read))
        .or_else(|| crate::mounted_volume::claim_mounted_directory_sector().map(SectorClaim::Directory))
        .map(WorkClaim::Sector)
}

/// A queued mounted sector must wake the root Receive even when no unrelated IRQ arrives.
/// The entered physical command owns its completion; only a vacant slot can be redriven.
fn queued_timer_work() -> bool {
    native_disk_relation::native_storage_route().is_some()
        && crate::mounted_volume::mounted_sector_claimable() == Some(true)
}

fn claimable_timer_work() -> bool {
    (unsafe { (&*core::ptr::addr_of!(PENDING)).is_none() }) && queued_timer_work()
}

pub(super) fn publish_wake(now_100ns: u64) {
    let deadline = now_100ns.saturating_add(MOUNTED_RETRY_DELAY_100NS);
    if claimable_timer_work() { WAKE_LATENCY.publish(now_100ns, deadline); }
    else { WAKE_UNSAMPLED.fetch_add(1, Ordering::Relaxed); }
    WAKE.publish(deadline);
}

pub(super) fn wake_due(now_100ns: u64) -> u64 {
    let epoch = WAKE_LATENCY.current_epoch();
    let due = WAKE.wake_due(now_100ns, claimable_timer_work());
    if due { if let Some(epoch) = epoch { WAKE_LATENCY.due(epoch, now_100ns); } }
    u64::from(due)
}

/// A nested timer may have marked the queued sector notified while the physical caller keeps
/// the root loop unavailable. Only the outer service owner can claim the sector; yielding the
/// exact nested frame lets that owner resume without sending another timer notification.
pub(super) fn nested_ready() -> bool {
    if NATIVE_PENDING_IRP.load(Ordering::Acquire) != 0 || !queued_timer_work() {
        return false;
    }
    WAKE.due_for_outer(monotonic_time_100ns(), true)
}

pub(super) fn next_deadline(_now_100ns: u64) -> Option<u64> {
    let claimable = claimable_timer_work();
    if !claimable && crate::mounted_volume::mounted_sector_claimable() == Some(false) {
        if let Some(epoch) = WAKE_LATENCY.current_epoch() { WAKE_LATENCY.empty(epoch); }
    }
    WAKE.next_deadline(claimable)
}

unsafe fn next_claim() -> Option<WorkClaim> {
    let snapshot = || crate::writable_fs::native_snapshot_io::claim_next_native_snapshot_io()
        .map(WorkClaim::Snapshot);
    let claim = if *core::ptr::addr_of!(SNAPSHOT_FIRST) {
        snapshot().or_else(next_sector_claim)
    } else {
        next_sector_claim().or_else(snapshot)
    };
    if claim.is_some() {
        *core::ptr::addr_of_mut!(SNAPSHOT_FIRST) = !*core::ptr::addr_of!(SNAPSHOT_FIRST);
    }
    claim
}

fn packet_capacity(command: &ScsiBlockCommand) -> Option<usize> {
    64usize.checked_add(nt_io_manager::scsi_srb_transport::WDM_X64_LEGACY_SRB_SIZE)?
        .checked_add(command.data_len() as usize)?
        .checked_add(command.sense_len() as usize)
}

fn terminal_data<'a>(
    command: &ScsiBlockCommand,
    route: nt_io_manager::scsi_srb_transport::ScsiSrbRoute,
    irp: IrpId,
    terminal: &'a Terminal,
) -> Result<&'a [u8], nt_status::NtStatus> {
    if !terminal.status.is_success() {
        return Err(terminal.status);
    }
    let packet = decode_scsi_completion(&terminal.packet, route, irp)
        .map_err(|_| nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32))?;
    command.verify_completion(packet.srb, packet.data.len())
        .map_err(|_| nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32))?;
    match command.kind() {
        nt_io_manager::scsi_block_command::BlockCommandKind::Read => Ok(packet.data),
        nt_io_manager::scsi_block_command::BlockCommandKind::Write
        | nt_io_manager::scsi_block_command::BlockCommandKind::Flush => Ok(&[]),
        nt_io_manager::scsi_block_command::BlockCommandKind::Capacity =>
            Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
    }
}

fn settle(pending: Pending, terminal: Terminal) {
    let result = terminal_data(&pending.command, pending.route.scsi, pending.irp, &terminal);
    let operation = match pending.command.kind() {
        nt_io_manager::scsi_block_command::BlockCommandKind::Read => nt_ahci::IoOperation::Read,
        nt_io_manager::scsi_block_command::BlockCommandKind::Write => nt_ahci::IoOperation::Write,
        nt_io_manager::scsi_block_command::BlockCommandKind::Flush => nt_ahci::IoOperation::Barrier,
        nt_io_manager::scsi_block_command::BlockCommandKind::Capacity => unreachable!("mounted block capacity request"),
    };
    let census = match pending.claim.source() {
        nt_fs::BlockSource::Fat => &NATIVE_FAT_CENSUS,
        nt_fs::BlockSource::Snapshot => &NATIVE_SNAPSHOT_CENSUS,
    };
    census.record(operation, pending.started_ticks, crate::disk_census_ticks(),
        (pending.command.data_len() / 512) as u64, result.is_err());
    if result.is_ok() {
        crate::fs_loader::complete_exec_native_block(pending.ticket, pending.command.data_len() as u64)
            .expect("exact native block ticket lost");
    } else {
        crate::fs_loader::complete_exec_native_block_failure(pending.ticket)
            .expect("exact failed native block ticket lost");
    }
    // Returned commands are terminal inline; pending commands reach settle only after the
    // authenticated completion and strict ACK in poll_pending. Never publish a refused or
    // malformed packet, and never shadow writable overlay, file data, or snapshot sectors.
    if let Ok(bytes) = &result {
        unsafe { publish_metadata_shadow(pending.route, &pending.claim, bytes) };
    }
    pending.claim.complete_physical(result);
    let finished = crate::disk_census_ticks();
    NATIVE_TERMINAL_SETTLE_PHASE.record(pending.terminal_ticks, finished);
    NATIVE_LAST_SETTLED_TICKS.store(finished, Ordering::Relaxed);
}

unsafe fn poll_pending() -> usize {
    let slot = &mut *core::ptr::addr_of_mut!(PENDING);
    let Some(pending) = slot.as_mut() else { return 0; };
    if pending.terminal.is_none() {
        let Some(completion) = completed_device_control_irp_exact(pending.irp.raw()) else {
            return 0;
        };
        if completion.client_id != IO_MANAGER_COMPONENT_ID
            || completion.driver_id != pending.route.driver_id.raw()
            || completion.completion_driver_id != pending.route.driver_id.raw()
            || completion.device_id != pending.route.scsi.pdo.raw()
            || completion.completion_device_id != pending.route.scsi.pdo.raw()
            || completion.requestor_tid != pending.requestor_tid
            || completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        {
            // Identity uncertainty retains the ticket and packet; a numeric IRP is not proof.
            return 0;
        }
        let status = nt_status::NtStatus(completion.status as i32);
        let mut packet = Vec::new();
        if status.is_success() {
            let Some(capacity) = packet_capacity(&pending.command) else { return 0; };
            if packet.try_reserve_exact(capacity).is_err() { return 0; }
            packet.resize(capacity, 0);
            if copy_completed_irp_output_exact(pending.irp.raw(), 0, &mut packet) != Ok(capacity) {
                return 0;
            }
        }
        pending.terminal = Some(Terminal { status, packet });
        pending.terminal_ticks = crate::disk_census_ticks();
        NATIVE_DISPATCH_TERMINAL_PHASE.record(pending.started_ticks, pending.terminal_ticks);
        NATIVE_DISPATCH_RETURN_TERMINAL_PHASE.record(
            pending.dispatch_returned_ticks, pending.terminal_ticks,
        );
    }
    if acknowledge_completed_irp_strict(pending.irp.raw()).is_err() {
        return 0;
    }
    let mut pending = slot.take().expect("acknowledged native sector owner disappeared");
    NATIVE_PENDING_IRP.store(0, Ordering::Release);
    let terminal = pending.terminal.take().unwrap();
    settle(pending, terminal);
    1
}

// Native dispatch may enter a hosted component pump before its IRP is returned. A nested
// receive may then service a retained header recheck, but must not reenter this executor while
// the first command still owns its unreturned dispatch and physical ticket.
static SERVICE_ACTIVE: AtomicBool = AtomicBool::new(false);

struct NativeServiceGuard {
    wake_attempt: Option<nt_time::RetryWakeAttempt<'static>>,
}

impl NativeServiceGuard {
    fn enter() -> Option<Self> {
        SERVICE_ACTIVE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok().map(|_| {
                if claimable_timer_work() {
                    if let Some(epoch) = WAKE_LATENCY.current_epoch() {
                        WAKE_LATENCY.service(epoch, monotonic_time_100ns());
                    }
                }
                Self {
                    // Snapshot the published retry even while a physical command is pending.
                    // Settling it may expose another already-queued sector without a new publish.
                    wake_attempt: WAKE.begin_redrive(monotonic_time_100ns(), queued_timer_work()),
                }
            })
    }
}

impl Drop for NativeServiceGuard {
    fn drop(&mut self) {
        if let Some(attempt) = self.wake_attempt.take() {
            let now = monotonic_time_100ns();
            let deadline = now.saturating_add(MOUNTED_RETRY_DELAY_100NS);
            if claimable_timer_work() && attempt.retry_at(deadline) {
                if let Some(epoch) = WAKE_LATENCY.current_epoch() {
                    WAKE_LATENCY.reschedule(epoch, deadline);
                } else { WAKE_LATENCY.follow_on(now, deadline); }
                crate::service_sec_image::request_mounted_native_timer_rearm_after_service();
            }
        }
        if crate::mounted_volume::mounted_sector_claimable() == Some(false) {
            if let Some(epoch) = WAKE_LATENCY.current_epoch() { WAKE_LATENCY.empty(epoch); }
        }
        SERVICE_ACTIVE.store(false, Ordering::Release);
    }
}

/// Complete bounded cached claims and drive at most one physical command per service turn.
/// Backends only publish claims.
pub(super) unsafe fn service() -> usize {
    let Some(_guard) = NativeServiceGuard::enter() else {
        NATIVE_SERVICE_GUARD_BUSY.fetch_add(1, Ordering::Relaxed);
        return 0;
    };
    let settled = if (&*core::ptr::addr_of!(PENDING)).is_some() {
        let settled = poll_pending();
        if settled == 0 {
            NATIVE_SERVICE_PENDING_WAIT.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        settled
    } else { 0 };
    if native_disk_relation::native_storage_route().is_some() {
        let mut first_claim = true;
        let mut cached_in_turn = 0usize;
        // Each cached completion may synchronously publish another FAT lookup sector.
        // Reacquire the published physical route before each claim; the first non-cache
        // result ends this turn even if its provider returned inline or refused entry.
        let driven = drain_cached_claims(CACHE_CLAIMS_PER_TURN,
            || {
                let route = native_disk_relation::native_storage_route()?;
                let search_started = crate::disk_census_ticks();
                let epoch = WAKE_LATENCY.current_epoch();
                let claim = next_claim();
                if matches!(claim.as_ref(), Some(WorkClaim::Sector(_))) {
                    if let Some(epoch) = epoch { WAKE_LATENCY.claim_sector(epoch, monotonic_time_100ns()); }
                }
                NATIVE_CLAIM_SEARCH_PHASE.record(search_started, crate::disk_census_ticks());
                if first_claim {
                    if claim.is_some() {
                        if settled == 0 {
                            NATIVE_SERVICE_CLAIM_HIT_FRESH.fetch_add(1, Ordering::Relaxed);
                        } else {
                            NATIVE_SERVICE_CLAIM_HIT_AFTER_SETTLE.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if settled == 0 {
                        NATIVE_SERVICE_CLAIM_MISS_FRESH.fetch_add(1, Ordering::Relaxed);
                    } else {
                        NATIVE_SERVICE_CLAIM_MISS_AFTER_SETTLE.fetch_add(1, Ordering::Relaxed);
                    }
                    first_claim = false;
                }
                claim.map(|claim| (route, claim))
            },
            |(route, claim)| {
                let result = dispatch_claim(route, claim, None);
                if result == CacheClaimStep::Cached { cached_in_turn += 1; }
                result
            });
        METADATA_EXTRA_HITS_IN_TURN.fetch_add(
            cached_in_turn.saturating_sub(1) as u64, Ordering::Relaxed);
        return settled.saturating_add(driven);
    }
    let Some(route) = native_disk_relation::retained_native_storage_recheck_route() else {
        return settled;
    };
    let Some(wal_authority) = retained_native_storage_wal_scsi_authority(route) else {
        return settled;
    };
    let claim = crate::driver_launch::native_storage_relation_recheck_id()
        .and_then(|id| crate::writable_fs::native_snapshot_io::claim_relation_header_recheck(id))
        .or_else(|| crate::writable_fs::native_snapshot_io::claim_retained_relation_wal_io());
    let Some(claim) = claim.map(WorkClaim::Snapshot) else { return settled; };
    settled.saturating_add(dispatch_claim(route, claim, wal_authority).progress())
}

/// Under a parked Receive parent, drain an already-entered physical command through its exact
/// completion/ACK. When that single slot is vacant, admit only the selected registry owner's
/// command under the normally published native route.
unsafe fn service_registry_exact(
    id: u64,
    selected: fn() -> Option<u64>,
    claim: unsafe fn(u64) -> Option<crate::writable_fs::native_snapshot_io::SnapshotClaim>,
) -> usize {
    if id == 0 || selected() != Some(id) {
        return 0;
    }
    let Some(_guard) = NativeServiceGuard::enter() else { return 0; };
    if (&*core::ptr::addr_of!(PENDING)).is_some() {
        return poll_pending();
    }
    let Some(route) = native_disk_relation::native_storage_route() else { return 0; };
    let Some(claim) = claim(id) else { return 0; };
    dispatch_claim(route, WorkClaim::Snapshot(claim), None).progress()
}

pub(super) unsafe fn service_registry_recheck(id: u64) -> usize {
    service_registry_exact(id,
        crate::registry_mutation_work::pending_provider_header_recheck,
        crate::writable_fs::native_snapshot_io::claim_registry_header_recheck)
}

pub(super) unsafe fn service_registry_wal(id: u64) -> usize {
    service_registry_exact(id,
        crate::registry_mutation_work::pending_provider_native_wal_io,
        crate::writable_fs::native_snapshot_io::claim_registry_wal_for)
}

unsafe fn dispatch_claim(
    route: native_disk_relation::NativeStorageRoute,
    claim: WorkClaim,
    wal_authority: Option<PendingScsiProofAuthority>,
) -> CacheClaimStep {
    let claim_started_ticks = crate::disk_census_ticks();
    if claim.mount() != route.mount.value() {
        claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return CacheClaimStep::Stop(1);
    }
    let Some(operation) = claim.operation() else {
        claim.refuse_unentered(nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32));
        return CacheClaimStep::Stop(1);
    };
    // A hit is an exact copied sector from an earlier authenticated terminal/ACK under this
    // physical mount and provider generation. The Executive-owned poison linearizes before any
    // possible same-disk write enters its provider. Complete only the retained logical claim;
    // no physical ticket or fabricated provider terminal is created.
    if let Some((sector, census)) = metadata_sector(&claim) {
        if let Some(fence) = metadata_fence_for(route) {
            let key = (route.mount.value(), route.key);
            if fence.eligible(&metadata_disk(route.scsi), &key) {
                if let Some(bytes) = metadata_shadow_for(route).lookup(key, sector) {
                    let bytes = *bytes;
                    census.hits.fetch_add(1, Ordering::Relaxed);
                    METADATA_READ_THROUGH_HITS.fetch_add(1, Ordering::Relaxed);
                    claim.complete_cached(&bytes);
                    return CacheClaimStep::Cached;
                }
            }
        }
    }
    let Ok(ticket) = crate::fs_loader::enter_exec_native_block(
        route.mount, claim.source(), operation,
    ) else {
        claim.release_unentered();
        return CacheClaimStep::Stop(0);
    };
    let command = match operation {
        nt_fs::BlockOperation::Read { lba, sectors } => ScsiBlockCommand::read(lba, sectors),
        nt_fs::BlockOperation::Write { lba, sectors } => ScsiBlockCommand::write(lba, sectors),
        nt_fs::BlockOperation::Flush => Ok(ScsiBlockCommand::flush()),
    };
    let Ok(command) = command else {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered invalid native command ticket lost");
        claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return CacheClaimStep::Stop(1);
    };
    let Some(capacity) = packet_capacity(&command) else {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered native packet ticket lost");
        claim.release_unentered();
        return CacheClaimStep::Stop(0);
    };
    let mut output = Vec::new();
    if output.try_reserve_exact(capacity).is_err() {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered native packet ticket lost");
        claim.release_unentered();
        return CacheClaimStep::Stop(0);
    }
    output.resize(capacity, 0);
    let Ok(parameters) = ScsiParameters::from_wire(
        route.scsi, *command.srb(), command.data_len(), command.sense_len(),
    ) else {
        crate::fs_loader::cancel_unentered_exec_native_block(ticket)
            .expect("unentered native SCSI parameters ticket lost");
        claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        return CacheClaimStep::Stop(1);
    };
    let mut read_input = Vec::new();
    let input = if matches!(operation, nt_fs::BlockOperation::Write { .. }) {
        let Some(bytes) = claim.write_input() else {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("unentered native write ticket lost");
            claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return CacheClaimStep::Stop(1);
        };
        if bytes.len() != command.data_len() as usize {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("unentered native write length ticket lost");
            claim.refuse_unentered(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return CacheClaimStep::Stop(1);
        }
        bytes
    } else {
        if read_input.try_reserve_exact(command.data_len() as usize).is_err() {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("unentered native input ticket lost");
            claim.release_unentered();
            return CacheClaimStep::Stop(0);
        }
        read_input.resize(command.data_len() as usize, 0);
        read_input.as_slice()
    };
    let caller = crate::initial_system_driver_caller();
    let requestor_tid = u64::from(caller.original_thread().thread_id());
    let request = ExternalFileIrpRequest {
        client: ClientId(IO_MANAGER_COMPONENT_ID),
        device_id: route.scsi.pdo,
        file_id: None,
        user_data: 0,
        requestor_tid,
        major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
        parameters: IoParameters::Scsi(parameters),
        stack_flags: StackFlags::empty(),
        initial_information: 0,
    };
    let _authority_guard = if let Some(authority) = wal_authority {
        match activate_pending_scsi_proof_authority(authority) {
            Ok(guard) => Some(guard),
            Err(_) => {
                crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                    .expect("unentered WAL authority ticket lost");
                claim.release_unentered();
                return CacheClaimStep::Stop(0);
            }
        }
    } else { None };
    let started_ticks = crate::disk_census_ticks();
    let dispatch = hosted_file_owners::dispatch(
        caller, request, input, &output, ExternalFileIrpDispatchPolicy::ScsiAtDevice,
    );
    let dispatch_returned_ticks = crate::disk_census_ticks();
    drop(_authority_guard);
    match dispatch {
        Ok(hosted_file_owners::DispatchResult::Returned { irp_id, status, buffers, .. }) => {
            NATIVE_DISPATCH_CALL_PHASE.record(started_ticks, dispatch_returned_ticks);
            NATIVE_PREP_PHASE.record(claim_started_ticks, started_ticks);
            record_inter_command_gap(claim_started_ticks);
            let terminal_ticks = crate::disk_census_ticks();
            NATIVE_DISPATCH_TERMINAL_PHASE.record(started_ticks, terminal_ticks);
            record_entered_installed_read(&claim);
            claim.mark_entered();
            crate::fs_loader::mark_entered_exec_native_block(ticket)
                .expect("returned native block ticket lost");
            observe_metadata_shadow(route, &claim);
            let (_, packet) = buffers.into_parts();
            settle(Pending { claim, ticket, route, command, irp: irp_id,
                requestor_tid, terminal: None, started_ticks, dispatch_returned_ticks,
                terminal_ticks },
                Terminal { status, packet });
            CacheClaimStep::Stop(1)
        }
        Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
            NATIVE_DISPATCH_CALL_PHASE.record(started_ticks, dispatch_returned_ticks);
            NATIVE_PREP_PHASE.record(claim_started_ticks, started_ticks);
            record_inter_command_gap(claim_started_ticks);
            record_entered_installed_read(&claim);
            claim.mark_entered();
            crate::fs_loader::mark_entered_exec_native_block(ticket)
                .expect("pending native block ticket lost");
            observe_metadata_shadow(route, &claim);
            let source = claim.source();
            let bytes = command.data_len();
            *core::ptr::addr_of_mut!(PENDING) = Some(Pending {
                claim, ticket, route, command, irp: irp_id, requestor_tid, terminal: None,
                started_ticks, dispatch_returned_ticks, terminal_ticks: 0,
            });
            NATIVE_PENDING_STARTED.store(started_ticks, Ordering::Relaxed);
            NATIVE_PENDING_BYTES.store(bytes as u64, Ordering::Relaxed);
            NATIVE_PENDING_SOURCE.store(u64::from(source == nt_fs::BlockSource::Snapshot), Ordering::Relaxed);
            NATIVE_PENDING_IRP.store(irp_id.raw(), Ordering::Release);
            // The nested dispatch pump may already have drained this command's IRQ/DPC.
            // Probe once now that its exact physical owner is installed; an unproven
            // terminal or uncertain ACK leaves the slot occupied for a later wakeup.
            CacheClaimStep::Stop(1 + poll_pending())
        }
        Err(status) => {
            crate::fs_loader::cancel_unentered_exec_native_block(ticket)
                .expect("refused native block ticket lost");
            if status == nt_status::NtStatus::DEVICE_BUSY
                || status == nt_status::NtStatus::INSUFFICIENT_RESOURCES {
                claim.release_unentered();
                CacheClaimStep::Stop(0)
            } else {
                claim.refuse_unentered(status);
                CacheClaimStep::Stop(1)
            }
        }
    }
}
