//! Native SYSTEM create ownership from before BEGIN through exact terminal ACK.

use crate::*;
use alloc::string::String;
use crate::exec_handler::registry_admission::HostedRegistryPublication;
use nt_config_client::*;
use nt_process::RegistryKeyHandlePublication;
use nt_process::native_handle::NativeThreadProcessReference;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_thread_start::amd64_context::UserApcContinuation;
use writable_fs::registry_wal::Journal as WalJournal;

struct HostedCaller {
    completion: HostedCompletion,
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    logical: ProviderLogicalCaller,
    reference: NativeThreadProcessReference,
    _continuation: UserApcContinuation,
}

enum HostedCompletion {
    Create {
        publication: HostedRegistryPublication,
        parent_owner: RegistryKeyHandlePublication,
        parent: KeyRef,
        leaf: String,
        grant: u32,
    },
    Existing {
        key_owner: RegistryKeyHandlePublication,
        kind: ExistingMutationKind,
    },
    SystemLocale { lease: SystemHiveKeyLease, locale_id: u32 },
}

#[derive(Clone, Copy)]
enum ExistingMutationKind {
    SetValue,
    DeleteValue,
    SetSecurity,
    DeleteKey,
}

#[must_use = "release the exact Key reservation or transfer it to retained mutation work"]
pub(crate) struct HostedExistingKey {
    key: KeyRef,
    target: CmSystemKeyTarget,
    owner: Option<RegistryKeyHandlePublication>,
}

impl HostedExistingKey {
    pub(crate) fn lease(&self) -> nt_config_client::SystemHiveKeyLease {
        self.target.lease
    }

    pub(crate) fn validate(&self, information: &nt_config_client::LeasedHiveKeyInformation) -> Result<(), u32> {
        let current = registry_key_targets::system(self.key).ok_or(0xC000_0008u32)?;
        if current.lease != self.target.lease
            || current.physical_path != self.target.physical_path
            || nt_hive_core::canon_path(&information.path)
                != nt_hive_core::canon_path(&self.target.physical_path)
        {
            return Err(0xC000_0008);
        }
        Ok(())
    }

    pub(crate) unsafe fn information(&self) -> Result<nt_config_client::LeasedHiveKeyInformation, u32> {
        let information = config_manager_query_leased_system_hive_key_information(self.lease())
            .map_err(|status| status as u32)?;
        self.validate(&information)?;
        Ok(information)
    }

    pub(crate) fn abort(mut self, handler: &mut ExecNtHandler) {
        if let Some(target) = self.owner.take().unwrap().abort(&mut handler.pm)
            .expect("retained existing Key admission") {
            handler.release_registry_key_target(target);
        }
    }
}

/// Bind a hidden PM reference before any CM query can reenter the executive.
pub(crate) fn retain_hosted_existing(handler: &mut ExecNtHandler, key: KeyRef) -> Result<HostedExistingKey, u32> {
    let target = registry_key_targets::system(key).ok_or(0xC000_0008u32)?;
    let tid = u32::try_from(handler.current_tid).map_err(|_| 0xC000_0008u32)?;
    let lifetime = handler.pm.thread_lifetime(tid).ok_or(0xC000_0008u32)?;
    let caller = handler.pm.capture_native_handle_caller(lifetime, nt_types::AccessMode::UserMode)?;
    let mut owner = handler.pm.reserve_native_registry_key_handle(caller, 0)?;
    if let Err(status) = owner.bind(&mut handler.pm, key, 0) {
        owner.abort(&mut handler.pm).expect("unbound existing Key reservation");
        return Err(status);
    }
    Ok(HostedExistingKey { key, target, owner: Some(owner) })
}

#[path = "registry_mutation_provider.rs"]
mod provider;
pub(crate) use provider::{
    submit_provider, submit_provider_existing, submit_provider_interface, DeferredRegistryExisting, ProviderRegistryResult,
    ProviderValueMutation,
};

enum Caller {
    Hosted(HostedCaller),
    Provider(provider::ProviderCaller),
}

impl Caller {
    fn logical(&self) -> Option<ProviderLogicalCaller> {
        match self {
            Self::Hosted(caller) => Some(caller.logical),
            Self::Provider(caller) => caller.logical,
        }
    }

    fn leaf(&self) -> &str {
        match self {
            Self::Hosted(HostedCaller { completion: HostedCompletion::Create { leaf, .. }, .. }) => leaf,
            Self::Hosted(_) => unreachable!("non-create mutation does not open a child"),
            Self::Provider(provider::ProviderCaller {
                admission: provider::ProviderAdmission::Create(admission), ..
            }) => &admission.leaf,
            Self::Provider(_) => unreachable!("existing provider Key does not open a child"),
        }
    }
}

type HostedContext<'a> = Option<(&'a mut ExecNtHandler, &'a mut nt_delay_execution::Queue)>;

fn system_mutation_storage(prepared: &PreparedSystemHiveMutation) -> Result<Vec<u8>, u32> {
    let journal = prepared.durable_journal();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(journal.len()).map_err(|_| 0xC000_009Au32)?;
    bytes.extend_from_slice(journal);
    Ok(bytes)
}

enum Phase {
    ProviderAdmit,
    Begin(CmMutationBeginAttempt<()>),
    Prepare(SystemHiveMutationPreparation<()>),
    Admit,
    Durable,
    Commit,
    CommitDurable,
    Open,
    Acknowledge,
    ReleasePublication(SystemHiveMutationAcknowledgement),
    Abort,
    Rollback,
    DurableAbort(SystemHiveMutationAbortReceipt),
    AcknowledgeAbort(SystemHiveMutationAbortReceipt),
    ReleaseRollback(SystemHiveMutationAbortAcknowledgement),
    Complete,
    ReadyReply,
    ReplyEntered,
    ReplySent,
    RevokeReply,
    RetypeReply,
    ReconcileRuntime,
    ProviderReplyEntered,
}

enum PersistenceOwner {
    Unadmitted,
    NoStorage,
    Admitting { recheck_id: u64, bytes: Vec<u8> },
    Legacy(writable_fs::registry_journal::Journal<()>),
    Wal(WalJournal),
}

/// One retained storage owner, chosen from the mounted snapshot format before CM COMMIT.
/// The exact CM receipt and typed acknowledgement are required to release either format.
pub(crate) struct MutationPersistence {
    owner: PersistenceOwner,
    binding: Option<SystemHiveMutationStorageBinding>,
    commit_receipt: Option<SystemHiveMutationCommitReceipt>,
    abort_receipt: Option<SystemHiveMutationAbortReceipt>,
    marker_complete: bool,
}

impl MutationPersistence {
    fn admitting(&self) -> bool { matches!(&self.owner, PersistenceOwner::Admitting { .. }) }

    fn claim_native_wal_io(&mut self) -> Result<Option<(nt_fs::AsyncWalIoRequest, nt_fs::BlockOperation, Vec<u8>, nt_memory_manager::SectionMountId)>, u32> {
        let PersistenceOwner::Wal(wal) = &mut self.owner else { return Ok(None); };
        let mount = wal.mount();
        wal.claim_native_io().map(|claim| claim.map(|(request, operation, input)| (request, operation, input, mount)))
    }

    fn native_wal_mut(&mut self) -> Option<&mut WalJournal> {
        match &mut self.owner { PersistenceOwner::Wal(wal) => Some(wal), _ => None }
    }

    pub(crate) fn new() -> Self {
        Self {
            owner: PersistenceOwner::Unadmitted,
            binding: None,
            commit_receipt: None,
            abort_receipt: None,
            marker_complete: false,
        }
    }

    pub(crate) fn has_journal(&self) -> bool {
        matches!(&self.owner, PersistenceOwner::Legacy(_) | PersistenceOwner::Wal(_))
    }

    pub(crate) unsafe fn admit(
        &mut self,
        prepared: &PreparedSystemHiveMutation,
        bytes: Vec<u8>,
    ) -> Result<(), u32> {
        if let PersistenceOwner::Admitting { recheck_id, .. } = &self.owner {
            let recheck_id = *recheck_id;
            let Some((lease, token, rechecked)) =
                writable_fs::snapshot_storage::take_rechecked_wal_continuation(recheck_id)?
            else { return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32); };
            let PersistenceOwner::Admitting { bytes: retained, .. } =
                core::mem::replace(&mut self.owner, PersistenceOwner::Unadmitted)
            else { unreachable!() };
            // The prepared CM bytes are checked again by admit_rechecked before its lease
            // moves into the WAL. The retained copy is the only bytes that may be persisted.
            drop(bytes);
            let wal = WalJournal::admit_rechecked(prepared, retained, lease, token, rechecked)?;
            self.owner = PersistenceOwner::Wal(wal);
            return Ok(());
        }
        assert!(matches!(&self.owner, PersistenceOwner::Unadmitted), "one storage owner per CM mutation");
        writable_fs::ensure_mounted()?;
        if bytes.is_empty() {
            // Volatile-only and idempotent CM mutations have semantic work but no durable
            // journal. They still COMMIT and ACK; no WAL serial is consumed.
            self.owner = PersistenceOwner::NoStorage;
            self.binding = Some(prepared.storage_binding());
            return Ok(());
        }
        match crate::fs_loader::exec_fs_mount_identity()
            .and_then(crate::fs_loader::exec_block_route_kind) {
            Some(nt_fs::BlockSourceKind::Draining) =>
                return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32),
            Some(nt_fs::BlockSourceKind::Native) => {
                let recheck_id = writable_fs::snapshot_storage::begin_wal_continuation_recheck()
                    .map_err(|status| if writable_fs::native_snapshot_io::admission_busy(status) {
                        nt_status::NtStatus::DEVICE_BUSY.raw() as u32
                    } else { status })?;
                self.binding = Some(prepared.storage_binding());
                self.owner = PersistenceOwner::Admitting { recheck_id, bytes };
                return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
            }
            _ => {}
        }
        self.owner = if writable_fs::legacy_snapshot_writes_allowed() {
            let journal = writable_fs::registry_journal::Journal::admit(bytes, ())
                .map_err(|(status, _, ())| status)?;
            PersistenceOwner::Legacy(journal)
        } else {
            let wal = WalJournal::admit(prepared, bytes)?;
            PersistenceOwner::Wal(wal)
        };
        self.binding = Some(prepared.storage_binding());
        Ok(())
    }

    pub(crate) fn make_durable(&mut self) -> Result<(), u32> {
        match &mut self.owner {
            PersistenceOwner::Legacy(journal) => journal.make_durable(),
            PersistenceOwner::Wal(wal) => wal.prepare(),
            PersistenceOwner::NoStorage | PersistenceOwner::Unadmitted => Ok(()),
            PersistenceOwner::Admitting { .. } => Err(nt_fs::STATUS_DEVICE_NOT_READY),
        }
    }

    pub(crate) fn begin_publication(&mut self) -> Result<(), u32> {
        if let PersistenceOwner::Legacy(journal) = &mut self.owner {
            journal.begin_publication()?;
        }
        Ok(())
    }

    pub(crate) fn commit_durable(
        &mut self,
        receipt: SystemHiveMutationCommitReceipt,
    ) -> Result<(), u32> {
        let binding = self.binding.ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
        if !receipt.matches_storage_binding(binding)
            || self.abort_receipt.is_some()
            || self.commit_receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        self.commit_receipt = Some(receipt);
        if let PersistenceOwner::Wal(wal) = &mut self.owner {
            if !self.marker_complete {
                wal.commit_marker(receipt)?;
                self.marker_complete = true;
            }
            wal.anchor()?;
        }
        Ok(())
    }

    pub(crate) fn rollback(&mut self) -> Result<(), u32> {
        match &mut self.owner {
            PersistenceOwner::Legacy(journal) => journal.rollback(),
            PersistenceOwner::Wal(_) | PersistenceOwner::NoStorage | PersistenceOwner::Unadmitted => Ok(()),
            PersistenceOwner::Admitting { .. } => Err(nt_fs::STATUS_DEVICE_NOT_READY),
        }
    }

    pub(crate) fn abort_after_receipt(
        &mut self,
        receipt: SystemHiveMutationAbortReceipt,
    ) -> Result<(), u32> {
        if self.binding.is_some_and(|binding| !receipt.matches_storage_binding(binding))
            || self.commit_receipt.is_some()
            || self.abort_receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        self.abort_receipt = Some(receipt);
        if let PersistenceOwner::Wal(wal) = &mut self.owner {
            wal.abort_prepared(receipt)?;
        }
        Ok(())
    }

    pub(crate) unsafe fn release_after_publication(
        &mut self,
        ack: SystemHiveMutationAcknowledgement,
    ) -> Result<(), u32> {
        if self.commit_receipt != Some(ack.receipt()) {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        match core::mem::replace(&mut self.owner, PersistenceOwner::Unadmitted) {
            PersistenceOwner::NoStorage => {}
            PersistenceOwner::Admitting { recheck_id, bytes } => {
                self.owner = PersistenceOwner::Admitting { recheck_id, bytes };
                return Err(nt_fs::STATUS_DEVICE_NOT_READY);
            }
            PersistenceOwner::Unadmitted => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
            PersistenceOwner::Legacy(journal) => match journal.release_after_publication() {
                Ok(()) => {}
                Err(journal) => {
                    self.owner = PersistenceOwner::Legacy(journal);
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
            },
            PersistenceOwner::Wal(wal) => match wal.release_after_ack(ack) {
                Ok(()) => {}
                Err(wal) => {
                    self.owner = PersistenceOwner::Wal(wal);
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
            },
        }
        Ok(())
    }

    pub(crate) unsafe fn release_rolled_back(
        &mut self,
        ack: SystemHiveMutationAbortAcknowledgement,
    ) -> Result<(), u32> {
        if self.abort_receipt != Some(ack.receipt()) {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        if let PersistenceOwner::Admitting { recheck_id, .. } = &self.owner {
            let recheck_id = *recheck_id;
            match writable_fs::snapshot_storage::take_rechecked_wal_continuation(recheck_id) {
                Ok(None) => return Err(nt_fs::STATUS_DEVICE_NOT_READY),
                Err(status) => {
                    if writable_fs::snapshot_storage::recheck_was_aborted_no_effect(recheck_id) {
                        self.owner = PersistenceOwner::Unadmitted;
                        return Ok(());
                    }
                    return Err(status);
                }
                Ok(Some((lease, token, proof))) => {
                    if let Err((status, token, pair)) =
                        writable_fs::snapshot_storage::install_wal_continuation(
                            &lease, token, proof.into_pair()) {
                        core::mem::forget(lease);
                        core::mem::forget(token);
                        core::mem::forget(pair);
                        writable_fs::block_uncertain_snapshot_reserve();
                        return Err(status);
                    }
                    drop(lease);
                    self.owner = PersistenceOwner::Unadmitted;
                    return Ok(());
                }
            }
        }
        match core::mem::replace(&mut self.owner, PersistenceOwner::Unadmitted) {
            PersistenceOwner::NoStorage | PersistenceOwner::Unadmitted => {}
            PersistenceOwner::Admitting { recheck_id, bytes } => {
                self.owner = PersistenceOwner::Admitting { recheck_id, bytes };
                return Err(nt_fs::STATUS_DEVICE_NOT_READY);
            }
            PersistenceOwner::Legacy(journal) => match journal.release_rolled_back() {
                Ok(()) => {}
                Err(journal) => {
                    self.owner = PersistenceOwner::Legacy(journal);
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
            },
            PersistenceOwner::Wal(wal) => match wal.release_after_abort(ack) {
                Ok(()) => {}
                Err(wal) => {
                    self.owner = PersistenceOwner::Wal(wal);
                    return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
                }
            }
        }
        Ok(())
    }
}

struct Work {
    id: u64,
    caller: Caller,
    phase: Phase,
    prepared: Option<PreparedSystemHiveMutation>,
    persistence: MutationPersistence,
    receipt: Option<SystemHiveMutationCommitReceipt>,
    opening: Option<cm_key_ownership::PublicationOpen>,
    status: u32,
    cancelled: bool,
    commit_entered: bool,
    published: bool,
}

static mut ATTEMPTS: CmMutationBeginAttempts = CmMutationBeginAttempts::new();
static mut WORK: Vec<Option<Work>> = Vec::new();
static NEXT_WORK_ID: AtomicU64 = AtomicU64::new(1);

fn next_work_id() -> u64 {
    let id = NEXT_WORK_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(id, 0, "registry mutation work id exhausted");
    id
}
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicU64 = AtomicU64::new(0);
static SYSTEM_LOCALE_PENDING: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static mut EXECUTING: Option<ProviderLogicalCaller> = None;
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
const RETRY_DELAY: u64 = 10_000_000;

/// Includes work retained across a failed CM exchange or a storage effect. The bootstrap
/// handoff must wait for this count and the journal owner before moving Ps into the handler.
pub(crate) fn pending_count() -> u64 {
    PENDING.load(Ordering::Acquire)
}

pub(crate) fn redrive_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// The outer native block executor alone claims physical WAL commands. A selected work row is
/// temporarily moved out of this table, so skip it until redrive has restored the owner.
pub(crate) unsafe fn claim_next_native_wal_io() -> Option<writable_fs::native_snapshot_io::SnapshotClaim> {
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    for (index, row) in rows.iter_mut().enumerate() {
        if EXECUTING_INDEX.load(Ordering::Relaxed) == index as u64 { continue; }
        let Some(work) = row.as_mut() else { continue; };
        match work.persistence.claim_native_wal_io() {
            Ok(Some((request, operation, input, mount))) => {
                return Some(writable_fs::native_snapshot_io::SnapshotClaim::from_mutation(
                    mount, operation, input, work.id, request,
                ));
            }
            Ok(None) => {},
            Err(_) => {
                return None;
            }
        }
    }
    None
}

unsafe fn native_wal_by_id(id: u64) -> Result<&'static mut WalJournal, u32> {
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    rows.iter_mut().flatten().find(|work| work.id == id)
        .and_then(|work| work.persistence.native_wal_mut())
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)
}

pub(crate) unsafe fn mark_native_wal_io_entered(id: u64, request: nt_fs::AsyncWalIoRequest) -> Result<(), u32> {
    native_wal_by_id(id)?.mark_native_io_entered(request)
}

pub(crate) unsafe fn release_unentered_native_wal_io(id: u64, request: nt_fs::AsyncWalIoRequest) -> Result<(), u32> {
    native_wal_by_id(id)?.release_unentered_native_io(request)
}

pub(crate) unsafe fn refuse_unentered_native_wal_io(
    id: u64, request: nt_fs::AsyncWalIoRequest, status: nt_status::NtStatus,
) -> Result<(), u32> {
    let work = (&mut *core::ptr::addr_of_mut!(WORK)).iter_mut().flatten()
        .find(|work| work.id == id).ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let wal = work.persistence.native_wal_mut().ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    let refusal = wal.refuse_unentered_native_io(request)?;
    work.status = status.raw() as u32;
    if refusal == nt_fs::AsyncWalRefusal::NoEffect {
        work.phase = Phase::Rollback;
    }
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    Ok(())
}

pub(crate) unsafe fn complete_native_wal_io(
    id: u64, request: nt_fs::AsyncWalIoRequest, result: Result<&[u8], nt_status::NtStatus>,
) -> Result<(), u32> {
    let settled = native_wal_by_id(id)?.complete_native_io(request, result);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    settled
}

/// Failure returns both canonical owners unchanged; no CM mutation has been sent.
pub(crate) unsafe fn submit_hosted(
    handler: &mut ExecNtHandler,
    publication: HostedRegistryPublication,
    parent_owner: RegistryKeyHandlePublication,
    parent: KeyRef,
    leaf: String,
    grant: u32,
    expected_generation: u64,
    mutation: SystemHiveMutation<'_>,
) -> Result<(), (u32, HostedRegistryPublication, RegistryKeyHandlePublication)> {
    let _durable = allocator::enter_durable();
    let admission = (|| {
        let tcb = handler.hosted_thread_tcb(handler.current_tid).ok_or(0xC000_0008u32)?;
        let logical = handler.capture_provider_logical_caller(
            handler.pi, handler.current_tid, handler.current_badge, tcb,
        ).ok_or(0xC000_0008u32)?;
        if logical.thread() != publication.subject.caller().original_thread() {
            return Err(0xC000_0008);
        }
        let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT.ok_or(0xC000_00A3u32)?;
        let park = root_reply_park::RootReplyPark::prepare().ok_or(0xC000_009Au32)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let index = rows.iter().enumerate().find_map(|(index, row)|
            (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
                .then_some(index));
        if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?; }
        let actor = publication.subject.caller().original_thread();
        let requestor = handler.pm.capture_native_handle_caller(
            actor, nt_types::AccessMode::KernelMode,
        )?;
        let mut reference = handler.pm.reference_native_requestor(requestor)?;
        let attempt = match (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
            .reserve(mount, expected_generation, &[mutation], ())
        {
            Ok(attempt) => attempt,
            Err((status, ())) => {
                reference.release(&mut handler.pm).expect("unsubmitted registry caller");
                return Err(status as u32);
            }
        };
        Ok((park, attempt, logical, reference, index))
    })();
    let (park, attempt, logical, reference, index) = match admission {
        Ok(admission) => admission,
        Err(status) => return Err((status, publication, parent_owner)),
    };
    let caller = HostedCaller {
        completion: HostedCompletion::Create { publication, parent_owner, parent, leaf, grant },
        pi: handler.pi,
        tid: handler.current_tid,
        badge: handler.current_badge,
        reply: REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        logical,
        reference,
        _continuation: if handler.current_native_call_transport {
            UserApcContinuation::NativeCall
        } else {
            UserApcContinuation::Fault {
                resume_ip: handler.current_resume_ip,
                resume_sp: handler.current_sp,
                resume_flags: handler.current_flags,
            }
        },
    };
    assert_ne!(caller.reply, 0);
    let work = Some(Work {
        id: next_work_id(),
        caller: Caller::Hosted(caller), phase: Phase::Begin(attempt), prepared: None, persistence: MutationPersistence::new(),
        receipt: None, opening: None, status: 0,
        cancelled: false, commit_entered: false, published: false,
    });
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    match index {
        Some(index) => rows[index] = work,
        None => rows.push(work),
    }
    // The row owns the live Reply before ingress can select a replacement.
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

type HostedMutationAdmission = (
    root_reply_park::RootReplyPark,
    Option<usize>,
    ProviderLogicalCaller,
    NativeThreadProcessReference,
    CmMutationBeginAttempt<()>,
);

unsafe fn admit_hosted_mutation(
    handler: &mut ExecNtHandler,
    expected_generation: u64,
    mutation: SystemHiveMutation<'_>,
) -> Result<HostedMutationAdmission, u32> {
    let tcb = handler.hosted_thread_tcb(handler.current_tid).ok_or(0xC000_0008u32)?;
    let logical = handler.capture_provider_logical_caller(
        handler.pi, handler.current_tid, handler.current_badge, tcb,
    ).ok_or(0xC000_0008u32)?;
    if u64::from(logical.thread().thread_id()) != handler.current_tid {
        return Err(0xC000_0008);
    }
    let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT.ok_or(0xC000_00A3u32)?;
    let park = root_reply_park::RootReplyPark::prepare().ok_or(0xC000_009Au32)?;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)|
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
            .then_some(index));
    if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?; }
    let requestor = handler.pm.capture_native_handle_caller(
        logical.thread(), nt_types::AccessMode::KernelMode,
    )?;
    let mut reference = handler.pm.reference_native_requestor(requestor)?;
    let attempt = match (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
        .reserve(mount, expected_generation, &[mutation], ()) {
        Ok(attempt) => attempt,
        Err((status, ())) => {
            reference.release(&mut handler.pm).expect("unsubmitted registry caller");
            return Err(status as u32);
        }
    };
    Ok((park, index, logical, reference, attempt))
}

/// The existing Key remains referenced by an invisible handle until exact ACK and caller reply.
/// A failed admission has made no CM request and releases every reservation before returning.
pub(crate) unsafe fn submit_hosted_existing(
    handler: &mut ExecNtHandler,
    mut retained: HostedExistingKey,
    expected_generation: u64,
    mutation: SystemHiveMutation<'_>,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let kind = match &mutation {
        SystemHiveMutation::SetValue { .. } => ExistingMutationKind::SetValue,
        SystemHiveMutation::DeleteValue { .. } => ExistingMutationKind::DeleteValue,
        SystemHiveMutation::SetKeySecurity { .. } => ExistingMutationKind::SetSecurity,
        SystemHiveMutation::DeleteKey { .. } => ExistingMutationKind::DeleteKey,
        _ => {
            retained.abort(handler);
            return Err(0xC000_000Du32);
        }
    };
    let (park, index, logical, reference, attempt) = match admit_hosted_mutation(
        handler, expected_generation, mutation,
    ) {
        Ok(admitted) => admitted,
        Err(status) => {
            retained.abort(handler);
            return Err(status);
        }
    };
    let key_owner = retained.owner.take().expect("retained existing Key owner");
    let hosted = HostedCaller {
        completion: HostedCompletion::Existing { key_owner, kind },
        pi: handler.pi,
        tid: handler.current_tid,
        badge: handler.current_badge,
        reply: REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        logical,
        reference,
        _continuation: if handler.current_native_call_transport {
            UserApcContinuation::NativeCall
        } else {
            UserApcContinuation::Fault {
                resume_ip: handler.current_resume_ip,
                resume_sp: handler.current_sp,
                resume_flags: handler.current_flags,
            }
        },
    };
    assert_ne!(hosted.reply, 0);
    let work = Some(Work {
        id: next_work_id(),
        caller: Caller::Hosted(hosted), phase: Phase::Begin(attempt), prepared: None, persistence: MutationPersistence::new(),
        receipt: None, opening: None, status: 0,
        cancelled: false, commit_entered: false, published: false,
    });
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    match index {
        Some(index) => rows[index] = work,
        None => rows.push(work),
    }
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

/// The exact SYSTEM key lease and caller Reply remain owned until CM acknowledgement.
pub(crate) unsafe fn submit_hosted_system_locale(
    handler: &mut ExecNtHandler,
    lease: SystemHiveKeyLease,
    expected_generation: u64,
    path: &str,
    name: &str,
    data: &[u8],
    locale_id: u32,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let mutation = SystemHiveMutation::SetValue { path, name, value_type: 1, data };
    let (park, index, logical, reference, attempt) = match admit_hosted_mutation(
        handler, expected_generation, mutation,
    ) {
        Ok(admitted) => admitted,
        Err(status) => {
            let _ = config_manager_retire_system_hive_key(lease);
            return Err(status);
        }
    };
    let caller = HostedCaller {
        completion: HostedCompletion::SystemLocale { lease, locale_id },
        pi: handler.pi,
        tid: handler.current_tid,
        badge: handler.current_badge,
        reply: REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        logical,
        reference,
        _continuation: if handler.current_native_call_transport {
            UserApcContinuation::NativeCall
        } else {
            UserApcContinuation::Fault {
                resume_ip: handler.current_resume_ip,
                resume_sp: handler.current_sp,
                resume_flags: handler.current_flags,
            }
        },
    };
    assert_ne!(caller.reply, 0);
    let work = Some(Work {
        id: next_work_id(),
        caller: Caller::Hosted(caller), phase: Phase::Begin(attempt), prepared: None, persistence: MutationPersistence::new(),
        receipt: None, opening: None, status: 0,
        cancelled: false, commit_entered: false, published: false,
    });
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    match index {
        Some(index) => rows[index] = work,
        None => rows.push(work),
    }
    park.commit();
    SYSTEM_LOCALE_PENDING.fetch_add(1, Ordering::Release);
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

pub(crate) fn take_transferred() -> bool {
    TRANSFERRED.swap(false, Ordering::AcqRel)
}

pub(crate) fn system_locale_pending() -> bool {
    SYSTEM_LOCALE_PENDING.load(Ordering::Acquire) != 0
}

pub(crate) fn has_thread(tid: u64) -> bool {
    has_matching(|caller| u64::from(caller.thread().thread_id()) == tid)
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    has_matching(|caller| caller.pi() == pi
        && preserve_tid != Some(u64::from(caller.thread().thread_id())))
}

fn has_matching(predicate: impl Fn(ProviderLogicalCaller) -> bool) -> bool {
    unsafe {
        (*core::ptr::addr_of!(EXECUTING)).is_some_and(&predicate)
            || (&*core::ptr::addr_of!(WORK)).iter().flatten()
                .any(|work| !matches!(work.phase, Phase::ReconcileRuntime)
                    && work.caller.logical().is_some_and(&predicate))
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    let work = (PENDING.load(Ordering::Acquire) != 0).then(|| NEXT.load(Ordering::Acquire));
    let service = unsafe {
        spawn_hosts::shared_ingress::owner::runtime::retained_service_resume_next_deadline()
    };
    match (work, service) {
        (Some(work), Some(service)) => Some(work.min(service)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

/// Top-level only. The selected owner is moved, never borrowed, across component IPC.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue) {
    redrive_inner(Some((handler, queue)));
}

/// Bootstrap and provider pumps may progress provider work without inventing a hosted handler.
#[inline(never)]
pub(crate) unsafe fn redrive_provider() {
    // Keep the common empty/already-running path out of redrive_inner's large Work frame.
    // Nested hosted pumps can reach this call several times on the rootserver stack.
    if PENDING.load(Ordering::Acquire) == 0
        || monotonic_time_100ns() < NEXT.load(Ordering::Acquire)
        || ACTIVE.load(Ordering::Acquire)
    {
        return;
    }
    redrive_inner(None);
}

#[inline(never)]
unsafe fn redrive_inner(mut context: HostedContext<'_>) {
    if PENDING.load(Ordering::Acquire) == 0
        || monotonic_time_100ns() < NEXT.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let mut failed = false;
    let selected = {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let count = rows.len();
        let start = CURSOR.load(Ordering::Relaxed) as usize % count;
        (0..count).find_map(|step| {
            let index = (start + step) % count;
            if context.is_none() && rows[index].as_ref()
                .is_some_and(|work| matches!(work.caller, Caller::Hosted(_))) {
                return None;
            }
            rows[index].take().map(|work| (index, work))
        })
    };
    if let Some((index, mut work)) = selected {
        EXECUTING_INDEX.store(index as u64, Ordering::Relaxed);
        CURSOR.store(index as u64 + 1, Ordering::Relaxed);
        *core::ptr::addr_of_mut!(EXECUTING) = work.caller.logical();
        let mut completed = false;
        // Bound each sweep; long journals resume fairly on the next maintenance tick.
        for _ in 0..16 {
            *core::ptr::addr_of_mut!(EXECUTING) =
                if matches!(work.phase, Phase::ReconcileRuntime) { None } else { work.caller.logical() };
            match advance(&mut context, &mut work) {
                Ok(true) => { completed = true; break; }
                Ok(false) => {}
                Err(_) => { failed = true; break; }
            }
        }
        if completed {
            PENDING.fetch_sub(1, Ordering::Release);
        } else {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
        *core::ptr::addr_of_mut!(EXECUTING) = None;
        EXECUTING_INDEX.store(u64::MAX, Ordering::Relaxed);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(if failed { RETRY_DELAY } else { 0 }), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}

unsafe fn caller_cancelled(handler: &ExecNtHandler, caller: &HostedCaller) -> bool {
    spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(caller.reply)
        || handler.pm.thread(caller.logical.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(caller.logical.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
}

unsafe fn advance(
    context: &mut HostedContext<'_>,
    work: &mut Work,
) -> Result<bool, i32> {
    work.cancelled |= match &work.caller {
        Caller::Hosted(caller) => caller_cancelled(&*context.as_ref().unwrap().0, caller),
        Caller::Provider(caller) => caller.cancelled(),
    };
    if work.cancelled && work.status == 0 { work.status = 0xC000_0120; }
    match &mut work.phase {
        Phase::ProviderAdmit => {
            if work.cancelled {
                work.phase = Phase::Complete;
                return Ok(false);
            }
            let Caller::Provider(caller) = &work.caller else { unreachable!() };
            match caller.begin() {
                Ok(attempt) => work.phase = Phase::Begin(attempt),
                Err(status) => { work.status = status as u32; work.phase = Phase::Complete; }
            }
        }
        Phase::Begin(attempt) => {
            let attempts = &mut *core::ptr::addr_of_mut!(ATTEMPTS);
            if attempt.is_acknowledged() {
                if attempt.outcome_status() == Some(0) {
                    work.phase = Phase::Prepare(attempts.take_upload(attempt)?.into_preparation());
                } else if attempt.outcome_status() == Some(0xC000_0059u32 as i32)
                    && !work.cancelled
                    && matches!(&work.caller, Caller::Provider(provider::ProviderCaller {
                        admission: provider::ProviderAdmission::InterfaceRegister(_), ..
                    }))
                {
                    // The old BEGIN is durably ACKed with no effect. A concurrent writer may
                    // advance SYSTEM, but the original interface may retry only on the same
                    // mounted hive while its exact PDO and devnode still name that instance.
                    let rebase = (|| {
                        let generation = LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
                        let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT
                            .ok_or(0xC000_00A3u32 as i32)?;
                        let value = match &mut work.caller {
                            Caller::Provider(provider::ProviderCaller {
                                admission: provider::ProviderAdmission::InterfaceRegister(value), ..
                            }) => value,
                            _ => unreachable!(),
                        };
                        if mount != value.mount {
                            return Err(0xC000_00A3u32 as i32);
                        }
                        if generation <= attempt.expected_generation() {
                            return Err(0x8000_0011u32 as i32);
                        }
                        CONFIG_CLIENT_PTR.as_mut()
                            .ok_or(0xC000_00A3u32 as i32)?
                            .validate_system_hive_mount(value.mount, generation)?;
                        value.revalidate_for_revision_retry(
                            mount, attempt.expected_generation(), generation,
                        )?;
                        attempts.retry_acknowledged_revision(attempt, value.mount, generation)?;
                        value.expected_generation = generation;
                        Ok(())
                    })();
                    match rebase {
                        Ok(()) => return Ok(false),
                        Err(status) if status == 0x8000_0011u32 as i32 => return Err(status),
                        Err(status) => {
                            let _ = attempts.take_failure(attempt)?;
                            work.status = status as u32;
                            work.phase = Phase::Complete;
                        }
                    }
                } else {
                    let (status, ()) = attempts.take_failure(attempt)?;
                    work.status = status as u32;
                    work.phase = Phase::Complete;
                }
                return Ok(false);
            }
            let op = if attempt.server_nonce().is_none() {
                CmMutationBeginOperation::Query
            } else if attempt.outcome_status().is_none() {
                CmMutationBeginOperation::Begin
            } else {
                CmMutationBeginOperation::Acknowledge
            };
            let mut exchange = attempts.begin_exchange(attempt, op)?;
            let response = cm_mutation_transport::begin(&exchange);
            (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
                .complete_exchange(attempt, &mut exchange, response)?;
        }
        Phase::Prepare(preparation) => {
            use CmMutationPreparationPhase as P;
            if preparation.phase() == P::Prepared {
                let (prepared, ()) = preparation.take_prepared()?;
                work.prepared = Some(prepared);
                work.phase = Phase::Admit;
                return Ok(false);
            }
            if preparation.phase() == P::Cancelled {
                preparation.take_cancelled()?;
                work.phase = Phase::Complete;
                return Ok(false);
            }
            if preparation.phase() == P::Allocating && work.status == 0 {
                if let Err(status) = preparation.allocate_journal() {
                    work.status = status as u32;
                }
                return Ok(false);
            }
            let op = match preparation.phase() {
                P::AcknowledgingCancellation => CmMutationPreparationOperation::AcknowledgeCancellation,
                _ if work.status != 0 => CmMutationPreparationOperation::Cancel,
                P::Appending => CmMutationPreparationOperation::Append,
                P::Preparing => CmMutationPreparationOperation::Prepare,
                P::Pulling => CmMutationPreparationOperation::Pull,
                _ => unreachable!("registry preparation phase"),
            };
            let mut exchange = preparation.begin_exchange(op)?;
            let response = cm_mutation_transport::prepare(&exchange);
            if let Err(status) = preparation.complete_exchange(&mut exchange, response) {
                // Before COMMIT an acknowledged cancellation is safe even after a lost PREPARE.
                if work.status == 0 { work.status = status as u32; }
                return Err(status);
            }
        }
        Phase::Admit => {
            if work.cancelled && !work.persistence.admitting() {
                work.phase = Phase::Abort;
                return Ok(false);
            }
            let prepared = work.prepared.as_ref().unwrap();
            if let Err(status) = cm_mutation_transport::validate_storage(prepared) {
                work.status = status as u32;
                work.phase = Phase::Abort;
                return Ok(false);
            }
            let bytes = if work.persistence.admitting() { Vec::new() }
                else { system_mutation_storage(prepared).map_err(|status| status as i32)? };
            match work.persistence.admit(prepared, bytes) {
                Ok(()) => {
                    work.phase = if work.persistence.has_journal() { Phase::Durable } else { Phase::Commit };
                }
                Err(status) if status == nt_status::NtStatus::DEVICE_BUSY.raw() as u32 => {
                    return Err(status as i32)
                }
                Err(status) => {
                    work.status = status;
                    work.phase = Phase::Abort;
                }
            }
        }
        Phase::Durable => {
            if work.cancelled {
                work.phase = Phase::Rollback;
                return Ok(false);
            }
            work.persistence.make_durable().map_err(|status| status as i32)?;
            work.phase = Phase::Commit;
        }
        Phase::Commit => {
            if work.cancelled && !work.commit_entered {
                work.phase = if work.persistence.has_journal() { Phase::Rollback } else { Phase::Abort };
                return Ok(false);
            }
            if !work.commit_entered {
                work.persistence.begin_publication().map_err(|status| status as i32)?;
                // No IPC separates the storage barrier from recording COMMIT entry.
                work.commit_entered = true;
            }
            let receipt = cm_mutation_transport::commit(work.prepared.as_ref().unwrap())?;
            work.receipt = Some(receipt);
            work.phase = Phase::CommitDurable;
        }
        Phase::CommitDurable => {
            let receipt = work.receipt.expect("retained CM COMMIT receipt");
            work.persistence.commit_durable(receipt).map_err(|status| status as i32)?;
            let outcome = receipt.outcome();
            CM_RUNTIME_SYSTEM_MUTATION_COMMITS.fetch_add(1, Ordering::Relaxed);
            note_boot_progress(BootProgress::DurableRegistryPublication);
            match &work.caller {
                Caller::Hosted(HostedCaller { completion: HostedCompletion::Existing { kind, .. }, .. }) => {
                    match kind {
                        ExistingMutationKind::SetValue => {
                            CM_RUNTIME_SYSTEM_SET_VALUES.fetch_add(1, Ordering::Relaxed);
                        }
                        ExistingMutationKind::DeleteValue => {
                            CM_RUNTIME_SYSTEM_DELETE_VALUES.fetch_add(1, Ordering::Relaxed);
                        }
                        ExistingMutationKind::SetSecurity => {
                            CM_RUNTIME_SYSTEM_SET_SECURITY.fetch_add(1, Ordering::Relaxed);
                        }
                        ExistingMutationKind::DeleteKey => {
                            CM_RUNTIME_SYSTEM_DELETE_KEYS.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Caller::Hosted(HostedCaller { completion: HostedCompletion::SystemLocale { .. }, .. }) => {
                    CM_RUNTIME_SYSTEM_SET_VALUES.fetch_add(1, Ordering::Relaxed);
                }
                Caller::Provider(provider::ProviderCaller {
                    admission: provider::ProviderAdmission::Existing(admission), ..
                }) => match &admission.mutation {
                    provider::ProviderValueMutation::Set { .. } => {
                        CM_RUNTIME_SYSTEM_SET_VALUES.fetch_add(1, Ordering::Relaxed);
                    }
                    provider::ProviderValueMutation::Delete { .. } => {
                        CM_RUNTIME_SYSTEM_DELETE_VALUES.fetch_add(1, Ordering::Relaxed);
                    }
                },
                _ => { CM_RUNTIME_SYSTEM_CREATE_KEYS.fetch_add(1, Ordering::Relaxed); }
            }
            LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.fetch_max(outcome.generation, Ordering::AcqRel);
            if outcome.has_pending_device_action {
                if !CONFIG_DEVICE_ACTION_PENDING.swap(true, Ordering::AcqRel) {
                    config_manager_request_device_action_wake();
                }
            }
            work.phase = Phase::Open;
        }
        Phase::Open => {
            if matches!(&work.caller, Caller::Hosted(HostedCaller {
                completion: HostedCompletion::Existing { .. } | HostedCompletion::SystemLocale { .. }, ..
            }) | Caller::Provider(provider::ProviderCaller {
                admission: provider::ProviderAdmission::Existing(_)
                    | provider::ProviderAdmission::InterfaceRegister(_), ..
            })) {
                work.published = !work.cancelled;
                work.phase = Phase::Acknowledge;
                return Ok(false);
            }
            if work.cancelled && work.opening.is_none() {
                work.phase = Phase::Acknowledge;
                return Ok(false);
            }
            if work.opening.is_none() {
                let lease = match &work.caller {
                    Caller::Hosted(HostedCaller {
                        completion: HostedCompletion::Create { parent, .. }, ..
                    }) => registry_key_targets::system(*parent)
                        .expect("retained SYSTEM parent disappeared").lease,
                    Caller::Hosted(_) => unreachable!("non-create mutation does not open a child"),
                    Caller::Provider(provider::ProviderCaller {
                        admission: provider::ProviderAdmission::Create(admission), ..
                    }) => admission.parent_lease,
                    Caller::Provider(_) => unreachable!("existing provider Key does not open a child"),
                };
                work.opening = Some(cm_key_ownership::reserve_publication_open(lease, work.caller.leaf())?);
            }
            let Some(opened) = cm_key_ownership::resume_publication_open(work.opening.as_ref().unwrap())? else {
                return Ok(false);
            };
            work.opening = None;
            let result = match opened {
                Ok(opened) if work.cancelled => {
                    let _ = config_manager_retire_system_hive_key(opened.lease);
                    Err(work.status)
                }
                Ok(opened) => match registry_key_targets::install_system(CmSystemKeyTarget {
                    lease: opened.lease,
                    physical_path: nt_hive_core::canon_path(&opened.physical_path),
                }) {
                    Ok(target) => {
                        let result = publish_target(context, &mut work.caller, target);
                        work.published = result.is_ok();
                        result
                    }
                    Err(status) => {
                        let _ = config_manager_retire_system_hive_key(opened.lease);
                        Err(status)
                    }
                },
                Err(status) => Err(status as u32),
            };
            work.status = result.err().unwrap_or(0);
            work.phase = Phase::Acknowledge;
        }
        Phase::Acknowledge => {
            let ack = cm_mutation_transport::acknowledge(work.receipt.unwrap())?;
            work.phase = Phase::ReleasePublication(ack);
        }
        Phase::ReleasePublication(ack) => {
            work.persistence.release_after_publication(*ack).map_err(|status| status as i32)?;
            if let Caller::Hosted(HostedCaller {
                completion: HostedCompletion::SystemLocale { locale_id, .. }, ..
            }) = &work.caller {
                crate::exec_handler::publish_system_default_locale(
                    *locale_id, work.receipt.unwrap().outcome().generation,
                );
            }
            work.phase = Phase::Complete;
        }
        Phase::Abort => {
            let receipt = cm_mutation_transport::abort(work.prepared.as_ref().unwrap())?;
            work.phase = Phase::DurableAbort(receipt);
        }
        Phase::Rollback => {
            work.persistence.rollback().map_err(|status| status as i32)?;
            work.phase = Phase::Abort;
        }
        Phase::DurableAbort(receipt) => {
            work.persistence.abort_after_receipt(*receipt).map_err(|status| status as i32)?;
            work.phase = Phase::AcknowledgeAbort(*receipt);
        }
        Phase::AcknowledgeAbort(receipt) => {
            let ack = cm_mutation_transport::acknowledge_abort(*receipt)?;
            work.phase = Phase::ReleaseRollback(ack);
        }
        Phase::ReleaseRollback(ack) => {
            work.persistence.release_rolled_back(*ack).map_err(|status| status as i32)?;
            work.phase = Phase::Complete;
        }
        Phase::Complete => {
            match &mut work.caller {
                Caller::Hosted(caller) => {
                    let handler = &mut *context.as_mut().unwrap().0;
                    match &mut caller.completion {
                        HostedCompletion::Create { publication, parent_owner, .. } => {
                            crate::registry_security_audit::admission_error(
                                b"create-completion", &publication.path, work.status,
                                caller.pi, caller.tid,
                            );
                            if !work.published {
                                handler.abort_hosted_registry_publication(publication);
                            }
                            if let Some(target) = parent_owner.abort(&mut handler.pm)
                                .expect("retained registry create parent") {
                                handler.release_registry_key_target(target);
                            }
                        }
                        HostedCompletion::Existing { key_owner, kind } => {
                            if let Some(target) = key_owner.abort(&mut handler.pm)
                                .expect("retained existing Key") {
                                if work.status != 0 {
                                    if let Some(path) = handler.registry_target_path(target) {
                                        let operation: &[u8] = match kind {
                                            ExistingMutationKind::SetValue => b"set-value-completion",
                                            ExistingMutationKind::DeleteValue => b"delete-value-completion",
                                            ExistingMutationKind::SetSecurity => b"set-security-completion",
                                            ExistingMutationKind::DeleteKey => b"delete-key-completion",
                                        };
                                        crate::registry_security_audit::admission_error(
                                            operation, &path, work.status, caller.pi, caller.tid,
                                        );
                                    }
                                }
                                handler.release_registry_key_target(target);
                            }
                        }
                        HostedCompletion::SystemLocale { lease, .. } => {
                            // Failed close effects remain owned by the CM lease journal.
                            let _ = config_manager_retire_system_hive_key(*lease);
                            SYSTEM_LOCALE_PENDING.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                }
                Caller::Provider(caller) => {
                    caller.cleanup(work.published && !work.cancelled)?;
                    work.phase = Phase::ProviderReplyEntered;
                    return caller.finish(work.status, work.published);
                }
            }
            work.phase = Phase::ReadyReply;
        }
        Phase::ReadyReply => {
            let Caller::Hosted(caller) = &mut work.caller else { unreachable!() };
            let handler = &mut *context.as_mut().unwrap().0;
            if work.cancelled {
                work.phase = Phase::RevokeReply;
                return Ok(false);
            }
            parked_reply::validate_saved(caller.reply).map_err(|status| status as i32)?;
            // An uncertain send cannot repeat cleanup or issue a second reply to this owner.
            work.phase = Phase::ReplyEntered;
            let delivered = crate::service_sec_image::complete_registry_mutation_reply(
                handler, caller.tid, caller.badge, caller.reply, work.status,
            );
            if !delivered { return Err(0xC000_00A3u32 as i32); }
            work.phase = Phase::ReplySent;
        }
        Phase::ReplySent => {
            let Caller::Hosted(caller) = &mut work.caller else { unreachable!() };
            let handler = &mut *context.as_mut().unwrap().0;
            parked_reply::retire_sent(caller.reply).map_err(|status| status as i32)?;
            if work.cancelled {
                work.phase = Phase::ReconcileRuntime;
                return Ok(false);
            }
            thread_wait_state_clear_badge_ready(handler, caller.badge);
            caller.reference.release(&mut handler.pm).expect("registry caller reference");
            return Ok(true);
        }
        Phase::ReplyEntered => {
            let Caller::Hosted(caller) = &work.caller else { unreachable!() };
            if spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(caller.reply)
                .map_err(|_| 0xC000_00A3u32 as i32)? {
                work.phase = Phase::ReplySent;
                return Ok(false);
            }
            if !work.cancelled { return Err(0xC000_00A3u32 as i32); }
            work.phase = Phase::RevokeReply;
        }
        Phase::RevokeReply => {
            let Caller::Hosted(caller) = &work.caller else { unreachable!() };
            if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(caller.reply) {
                parked_reply::revoke(caller.reply).map_err(|status| status as i32)?;
            }
            work.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            let Caller::Hosted(caller) = &work.caller else { unreachable!() };
            parked_reply::retype(caller.reply).map_err(|status| status as i32)?;
            work.phase = Phase::ReconcileRuntime;
        }
        Phase::ReconcileRuntime => {
            let Caller::Hosted(caller) = &mut work.caller else { unreachable!() };
            let (handler, queue) = context.as_mut().unwrap();
            if !hosted_termination::reconcile(handler, queue, caller.logical) {
                return Err(0xC000_00A3u32 as i32);
            }
            caller.reference.release(&mut handler.pm).expect("retired registry caller reference");
            return Ok(true);
        }
        Phase::ProviderReplyEntered => {
            let Caller::Provider(caller) = &mut work.caller else { unreachable!() };
            return caller.finish(work.status, work.published);
        }
    }
    Ok(false)
}

unsafe fn publish_target(context: &mut HostedContext<'_>, caller: &mut Caller, target: KeyRef) -> Result<(), u32> {
    match caller {
        Caller::Hosted(caller) => {
            let handler = &mut *context.as_mut().unwrap().0;
            if caller_cancelled(handler, caller) || !handler.validate_provider_logical_caller(caller.logical) {
                handler.release_registry_key_target(target);
                return Err(0xC000_004B);
            }
            let HostedCompletion::Create { publication, grant, .. } = &mut caller.completion else {
                unreachable!("existing Key has no target publication")
            };
            let saved_pi = handler.pi;
            handler.pi = caller.pi;
            let result = handler.finish_hosted_registry_publication(
                publication, target, *grant, true,
            );
            handler.pi = saved_pi;
            result
        }
        Caller::Provider(caller) => caller.bind_target(target).map_err(|status| status as u32),
    }
}
