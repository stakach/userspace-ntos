//! Depth-indexed transport for one hosted driver's private interrupt lane.
//!
//! The executive maps one control page and one dispatch/service page pair for every nesting depth.
//! Dispatch pages carry executive-to-lane calls. Service pages carry synchronous lane-to-executive
//! calls made while a dispatch is parked. Keeping the directions on different pages prevents a
//! nested provider call from overwriting its parent callback.
//!
//! The state machine assumes the private endpoint serializes exactly one executive actor and one
//! lane worker. It deliberately does not claim linearizability for arbitrary third-party callers
//! racing independent mask atomics. A dead worker is fenced by out-of-band TCB suspension before
//! its mappings are destroyed; shutdown is the graceful idle path, not a substitute for that hard
//! barrier. Grant identities carried here are authenticated lookup keys only. The executive must
//! resolve every key against its live generation-fenced lease registry before invoking a routine.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use crate::PAGE_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqLaneIdentity {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub lane_generation: u64,
}

impl HostedIrqLaneIdentity {
    pub const fn new(domain_id: u64, domain_cookie: u64, lane_generation: u64) -> Option<Self> {
        if domain_id == 0 || domain_cookie == 0 || lane_generation == 0 {
            None
        } else {
            Some(Self {
                domain_id,
                domain_cookie,
                lane_generation,
            })
        }
    }

    pub const fn ready_transport_words(self) -> [u64; 4] {
        [
            self.lane_generation,
            0,
            0,
            (HostedIrqLaneDirection::Dispatch as u32 as u64) << 8,
        ]
    }
}

pub const HOSTED_IRQ_ARENA_MAGIC: u64 = 0x4849_5251_4152_454e;
pub const HOSTED_IRQ_ARENA_VERSION: u16 = 2;
pub const HOSTED_IRQ_ARENA_DEPTH: usize = 16;
pub const HOSTED_IRQ_ARENA_ARGUMENT_CAP: usize = 12;
pub const HOSTED_IRQ_ARENA_RESULT_CAP: usize = 4;
pub const HOSTED_IRQ_ARENA_PAGE_COUNT: usize = 1 + HOSTED_IRQ_ARENA_DEPTH * 2;
pub const HOSTED_IRQ_ARENA_BYTES: u64 = HOSTED_IRQ_ARENA_PAGE_COUNT as u64 * PAGE_SIZE;

const LANE_BOOTING: u32 = 0;
const LANE_READY: u32 = 1;
const LANE_ACTIVE: u32 = 2;
const LANE_SHUTDOWN: u32 = 3;
const LANE_POISONED: u32 = 4;

const SLOT_IDLE: u32 = 0;
const SLOT_PUBLISHING: u32 = 1;
const SLOT_PENDING: u32 = 2;
const SLOT_RUNNING: u32 = 3;
const SLOT_COMPLETE: u32 = 4;
const SLOT_FAULTED: u32 = 5;
const SLOT_RELEASING: u32 = 6;
const SLOT_COMPLETING: u32 = 7;

const FAULT_EMPTY: u32 = 0;
const FAULT_PUBLISHING: u32 = 1;
const FAULT_RECORDED: u32 = 2;
const TRANSACTION_PUBLISHING: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HostedIrqLaneDirection {
    Dispatch = 1,
    Service = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HostedIrqTransactionClass {
    Interrupt = 1,
    Callback = 2,
    Dpc = 3,
}

impl HostedIrqTransactionClass {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Interrupt),
            2 => Some(Self::Callback),
            3 => Some(Self::Dpc),
            _ => None,
        }
    }
}

impl HostedIrqLaneDirection {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Dispatch),
            2 => Some(Self::Service),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HostedIrqDispatchKind {
    InterruptService = 1,
    DeferredProcedure = 2,
    ProviderCallback = 3,
}

impl HostedIrqDispatchKind {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::InterruptService),
            2 => Some(Self::DeferredProcedure),
            3 => Some(Self::ProviderCallback),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HostedIrqServiceKind {
    ProviderImport = 1,
    ProviderCallbackRequest = 2,
    QueueDpc = 3,
    AcquireActualLock = 4,
    ReleaseActualLock = 5,
}

impl HostedIrqServiceKind {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::ProviderImport),
            2 => Some(Self::ProviderCallbackRequest),
            3 => Some(Self::QueueDpc),
            4 => Some(Self::AcquireActualLock),
            5 => Some(Self::ReleaseActualLock),
            _ => None,
        }
    }

    pub const fn may_request_nested_dispatch(self) -> bool {
        matches!(self, Self::ProviderCallbackRequest)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum HostedIrqFaultKind {
    Protocol = 1,
    WorkerFault = 2,
    ServiceFault = 3,
    Transport = 4,
    BugCheck = 5,
}

impl HostedIrqFaultKind {
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Protocol),
            2 => Some(Self::WorkerFault),
            3 => Some(Self::ServiceFault),
            4 => Some(Self::Transport),
            5 => Some(Self::BugCheck),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedIrqArenaError {
    InvalidIdentity,
    InvalidLayout,
    InvalidDepth,
    InvalidCommand,
    InvalidResult,
    InvalidIrql,
    Busy,
    NotReady,
    NotPending,
    NotRunning,
    ResultNotReady,
    StaleTransaction,
    StaleToken,
    NestingViolation,
    SequenceExhausted,
    Shutdown,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqArenaLayout;

impl HostedIrqArenaLayout {
    pub const fn control_page_index() -> usize {
        0
    }

    pub const fn dispatch_page_index(depth: usize) -> Option<usize> {
        if depth < HOSTED_IRQ_ARENA_DEPTH {
            Some(1 + depth)
        } else {
            None
        }
    }

    pub const fn service_page_index(depth: usize) -> Option<usize> {
        if depth < HOSTED_IRQ_ARENA_DEPTH {
            Some(1 + HOSTED_IRQ_ARENA_DEPTH + depth)
        } else {
            None
        }
    }

    pub const fn page_offset(page_index: usize) -> Option<u64> {
        if page_index < HOSTED_IRQ_ARENA_PAGE_COUNT {
            Some(page_index as u64 * PAGE_SIZE)
        } else {
            None
        }
    }
}

/// Generation-bearing authority for a callback, import, DPC, or interrupt connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqGrantIdentity {
    pub owner_domain_id: u64,
    pub owner_domain_cookie: u64,
    pub grant_id: u64,
    pub grant_generation: u64,
}

impl HostedIrqGrantIdentity {
    pub const fn new(
        owner_domain_id: u64,
        owner_domain_cookie: u64,
        grant_id: u64,
        grant_generation: u64,
    ) -> Option<Self> {
        if owner_domain_id == 0
            || owner_domain_cookie == 0
            || grant_id == 0
            || grant_generation == 0
        {
            None
        } else {
            Some(Self {
                owner_domain_id,
                owner_domain_cookie,
                grant_id,
                grant_generation,
            })
        }
    }

    fn valid(self) -> bool {
        Self::new(
            self.owner_domain_id,
            self.owner_domain_cookie,
            self.grant_id,
            self.grant_generation,
        ) == Some(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqTransaction {
    pub lane_generation: u64,
    pub transaction: u64,
    pub class: HostedIrqTransactionClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqArenaToken {
    pub lane_generation: u64,
    pub transaction: u64,
    pub sequence: u64,
    pub depth: u8,
    pub direction: HostedIrqLaneDirection,
}

impl HostedIrqArenaToken {
    fn valid(self) -> bool {
        self.lane_generation != 0
            && self.transaction != 0
            && self.transaction != TRANSACTION_PUBLISHING
            && self.sequence != 0
            && (self.depth as usize) < HOSTED_IRQ_ARENA_DEPTH
    }

    pub const fn transport_words(self) -> [u64; 4] {
        [
            self.lane_generation,
            self.transaction,
            self.sequence,
            self.depth as u64 | (self.direction as u32 as u64) << 8,
        ]
    }

    pub fn from_transport_words(words: [u64; 4]) -> Option<Self> {
        if words[3] & !0xffff != 0 {
            return None;
        }
        let direction = match (words[3] >> 8) as u32 {
            1 => HostedIrqLaneDirection::Dispatch,
            2 => HostedIrqLaneDirection::Service,
            _ => return None,
        };
        let token = Self {
            lane_generation: words[0],
            transaction: words[1],
            sequence: words[2],
            depth: words[3] as u8,
            direction,
        };
        token.valid().then_some(token)
    }
}

/// One valid message received from a hosted interrupt lane's private endpoint.
///
/// READY is deliberately distinct from an arena token: it has no transaction or sequence and is
/// accepted only while bootstrapping a lane. Once a root replies to a parked arena call, the next
/// call may carry a different sequence, depth, and direction as the worker enters a synchronous
/// service or nested dispatch. The lane generation and transaction remain the transport fence;
/// the arena control/page state machines validate the stronger nesting rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedIrqTransportMessage {
    Ready,
    Token(HostedIrqArenaToken),
}

pub fn decode_hosted_irq_transport_message(
    identity: HostedIrqLaneIdentity,
    replying_to: Option<HostedIrqArenaToken>,
    words: [u64; 4],
) -> Option<HostedIrqTransportMessage> {
    if HostedIrqLaneIdentity::new(
        identity.domain_id,
        identity.domain_cookie,
        identity.lane_generation,
    ) != Some(identity)
    {
        return None;
    }
    let Some(parent) = replying_to else {
        return (words == identity.ready_transport_words())
            .then_some(HostedIrqTransportMessage::Ready);
    };
    if !parent.valid() || parent.lane_generation != identity.lane_generation {
        return None;
    }
    let token = HostedIrqArenaToken::from_transport_words(words)?;
    if token.lane_generation != identity.lane_generation || token.transaction != parent.transaction
    {
        return None;
    }
    Some(HostedIrqTransportMessage::Token(token))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqDispatchCommand {
    pub kind: HostedIrqDispatchKind,
    pub work_id: u64,
    pub routine: u64,
    pub object: u64,
    pub context: u64,
    pub entry_irql: u8,
    pub synchronize_irql: u8,
    pub grant: HostedIrqGrantIdentity,
    pub argument_count: u8,
    pub arguments: [u64; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
}

impl HostedIrqDispatchCommand {
    pub const fn transaction_class(self) -> HostedIrqTransactionClass {
        match self.kind {
            HostedIrqDispatchKind::InterruptService => HostedIrqTransactionClass::Interrupt,
            HostedIrqDispatchKind::DeferredProcedure => HostedIrqTransactionClass::Dpc,
            HostedIrqDispatchKind::ProviderCallback => HostedIrqTransactionClass::Callback,
        }
    }

    pub const fn execution_irql(self) -> u8 {
        match self.kind {
            HostedIrqDispatchKind::InterruptService => self.synchronize_irql,
            HostedIrqDispatchKind::DeferredProcedure | HostedIrqDispatchKind::ProviderCallback => {
                self.entry_irql
            }
        }
    }

    fn valid(self) -> bool {
        if self.work_id == 0
            || self.routine == 0
            || !self.grant.valid()
            || self.argument_count as usize > HOSTED_IRQ_ARENA_ARGUMENT_CAP
            || self.synchronize_irql < self.entry_irql
        {
            return false;
        }
        match self.kind {
            HostedIrqDispatchKind::InterruptService => self.entry_irql != 0,
            HostedIrqDispatchKind::DeferredProcedure => {
                self.entry_irql == 2 && self.synchronize_irql == 2
            }
            HostedIrqDispatchKind::ProviderCallback => self.synchronize_irql == self.entry_irql,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqServiceCommand {
    pub kind: HostedIrqServiceKind,
    pub service_id: u64,
    pub target_domain_id: u64,
    pub target_domain_cookie: u64,
    pub grant: HostedIrqGrantIdentity,
    pub argument_count: u8,
    pub arguments: [u64; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
}

impl HostedIrqServiceCommand {
    fn valid(self) -> bool {
        let common = self.service_id != 0
            && self.target_domain_id != 0
            && self.target_domain_cookie != 0
            && self.grant.valid()
            && self.argument_count as usize <= HOSTED_IRQ_ARENA_ARGUMENT_CAP;
        common
            && match self.kind {
                HostedIrqServiceKind::AcquireActualLock => self.argument_count == 0,
                HostedIrqServiceKind::ReleaseActualLock => {
                    self.argument_count == 1 && self.arguments[0] != 0
                }
                HostedIrqServiceKind::QueueDpc => {
                    self.argument_count == 4 && self.arguments[0] != 0
                }
                HostedIrqServiceKind::ProviderImport
                | HostedIrqServiceKind::ProviderCallbackRequest => true,
            }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqArenaResult {
    pub status: i32,
    pub faulted: bool,
    pub value_count: u8,
    pub values: [u64; HOSTED_IRQ_ARENA_RESULT_CAP],
}

impl HostedIrqArenaResult {
    fn valid(self) -> bool {
        self.value_count as usize <= HOSTED_IRQ_ARENA_RESULT_CAP
    }

    pub const fn claimed(&self) -> bool {
        self.value_count != 0 && self.values[0] != 0 && !self.faulted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqFaultRecord {
    pub kind: HostedIrqFaultKind,
    pub transaction: u64,
    pub sequence: u64,
    pub depth: u8,
    pub direction: HostedIrqLaneDirection,
    pub code: u64,
    pub instruction_pointer: u64,
    pub address: u64,
    pub parameters: [u64; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqArenaConfig {
    pub identity: HostedIrqLaneIdentity,
    pub component_kpcr_va: u64,
    pub stack_low: u64,
    pub stack_high: u64,
    pub high_irql: u8,
}

impl HostedIrqArenaConfig {
    fn valid(self) -> bool {
        HostedIrqLaneIdentity::new(
            self.identity.domain_id,
            self.identity.domain_cookie,
            self.identity.lane_generation,
        ) == Some(self.identity)
            && self.component_kpcr_va != 0
            && self.component_kpcr_va & (PAGE_SIZE - 1) == 0
            && self.stack_low != 0
            && self.stack_low & (PAGE_SIZE - 1) == 0
            && self.stack_high > self.stack_low
            && self.stack_high & (PAGE_SIZE - 1) == 0
            && self.high_irql != 0
            && self.high_irql <= 31
    }
}

impl HostedIrqFaultRecord {
    fn valid(self) -> bool {
        (self.depth as usize) < HOSTED_IRQ_ARENA_DEPTH && self.transaction != TRANSACTION_PUBLISHING
    }
}

/// Lane-wide identity, nesting, IRQL, shutdown, and sticky first-fault state.
#[repr(C, align(4096))]
pub struct HostedIrqArenaControl {
    magic: u64,
    version: u16,
    size: u16,
    max_depth: u16,
    reserved: u16,
    domain_id: u64,
    domain_cookie: u64,
    lane_generation: u64,
    component_kpcr_va: u64,
    stack_low: u64,
    stack_high: u64,
    lane_state: AtomicU32,
    current_irql: AtomicU32,
    high_irql: u32,
    reserved_irql: u32,
    transaction_next: AtomicU64,
    active_transaction: AtomicU64,
    active_transaction_class: AtomicU32,
    reserved_transaction: AtomicU32,
    dispatch_mask: AtomicU32,
    service_mask: AtomicU32,
    dispatch_running_mask: AtomicU32,
    service_running_mask: AtomicU32,
    depth_high_water: AtomicU32,
    reserved_depth: AtomicU32,
    fault_state: AtomicU32,
    fault_kind: AtomicU32,
    fault_transaction: AtomicU64,
    fault_sequence: AtomicU64,
    fault_depth_direction: AtomicU32,
    reserved_fault: AtomicU32,
    fault_code: AtomicU64,
    fault_instruction_pointer: AtomicU64,
    fault_address: AtomicU64,
    fault_parameters: [AtomicU64; 4],
    bugcheck_state: AtomicU32,
    reserved_bugcheck_state: AtomicU32,
    bugcheck_transaction: AtomicU64,
    bugcheck_sequence: AtomicU64,
    bugcheck_depth_direction: AtomicU32,
    reserved_bugcheck: AtomicU32,
    bugcheck_code: AtomicU64,
    bugcheck_instruction_pointer: AtomicU64,
    bugcheck_address: AtomicU64,
    bugcheck_parameters: [AtomicU64; 4],
    padding: [u8; 3792],
}

impl HostedIrqArenaControl {
    pub fn new(config: HostedIrqArenaConfig) -> Result<Self, HostedIrqArenaError> {
        if !config.valid() {
            return Err(HostedIrqArenaError::InvalidLayout);
        }
        let identity = config.identity;
        Ok(Self {
            magic: HOSTED_IRQ_ARENA_MAGIC,
            version: HOSTED_IRQ_ARENA_VERSION,
            size: core::mem::size_of::<Self>() as u16,
            max_depth: HOSTED_IRQ_ARENA_DEPTH as u16,
            reserved: 0,
            domain_id: identity.domain_id,
            domain_cookie: identity.domain_cookie,
            lane_generation: identity.lane_generation,
            component_kpcr_va: config.component_kpcr_va,
            stack_low: config.stack_low,
            stack_high: config.stack_high,
            lane_state: AtomicU32::new(LANE_BOOTING),
            current_irql: AtomicU32::new(0),
            high_irql: config.high_irql as u32,
            reserved_irql: 0,
            transaction_next: AtomicU64::new(0),
            active_transaction: AtomicU64::new(0),
            active_transaction_class: AtomicU32::new(0),
            reserved_transaction: AtomicU32::new(0),
            dispatch_mask: AtomicU32::new(0),
            service_mask: AtomicU32::new(0),
            dispatch_running_mask: AtomicU32::new(0),
            service_running_mask: AtomicU32::new(0),
            depth_high_water: AtomicU32::new(0),
            reserved_depth: AtomicU32::new(0),
            fault_state: AtomicU32::new(FAULT_EMPTY),
            fault_kind: AtomicU32::new(0),
            fault_transaction: AtomicU64::new(0),
            fault_sequence: AtomicU64::new(0),
            fault_depth_direction: AtomicU32::new(0),
            reserved_fault: AtomicU32::new(0),
            fault_code: AtomicU64::new(0),
            fault_instruction_pointer: AtomicU64::new(0),
            fault_address: AtomicU64::new(0),
            fault_parameters: [const { AtomicU64::new(0) }; 4],
            bugcheck_state: AtomicU32::new(FAULT_EMPTY),
            reserved_bugcheck_state: AtomicU32::new(0),
            bugcheck_transaction: AtomicU64::new(0),
            bugcheck_sequence: AtomicU64::new(0),
            bugcheck_depth_direction: AtomicU32::new(0),
            reserved_bugcheck: AtomicU32::new(0),
            bugcheck_code: AtomicU64::new(0),
            bugcheck_instruction_pointer: AtomicU64::new(0),
            bugcheck_address: AtomicU64::new(0),
            bugcheck_parameters: [const { AtomicU64::new(0) }; 4],
            padding: [0; 3792],
        })
    }

    pub fn identity(&self) -> Option<HostedIrqLaneIdentity> {
        if self.magic != HOSTED_IRQ_ARENA_MAGIC
            || self.version != HOSTED_IRQ_ARENA_VERSION
            || self.size as usize != core::mem::size_of::<Self>()
            || self.max_depth as usize != HOSTED_IRQ_ARENA_DEPTH
        {
            return None;
        }
        HostedIrqLaneIdentity::new(self.domain_id, self.domain_cookie, self.lane_generation)
    }

    pub fn identity_matches(&self, identity: HostedIrqLaneIdentity) -> bool {
        self.identity() == Some(identity)
    }

    fn check_identity(&self, identity: HostedIrqLaneIdentity) -> Result<(), HostedIrqArenaError> {
        if self.identity_matches(identity) {
            Ok(())
        } else {
            Err(HostedIrqArenaError::InvalidIdentity)
        }
    }

    fn check_lane_active(&self) -> Result<(), HostedIrqArenaError> {
        match self.lane_state.load(Ordering::Acquire) {
            LANE_ACTIVE => Ok(()),
            LANE_POISONED => Err(HostedIrqArenaError::Poisoned),
            LANE_SHUTDOWN => Err(HostedIrqArenaError::Shutdown),
            _ => Err(HostedIrqArenaError::NotReady),
        }
    }

    pub fn worker_mark_ready(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_identity(identity)?;
        self.lane_state
            .compare_exchange(
                LANE_BOOTING,
                LANE_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|state| match state {
                LANE_POISONED => HostedIrqArenaError::Poisoned,
                LANE_SHUTDOWN => HostedIrqArenaError::Shutdown,
                _ => HostedIrqArenaError::Busy,
            })
    }

    pub fn root_activate(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_identity(identity)?;
        self.lane_state
            .compare_exchange(LANE_READY, LANE_ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                LANE_POISONED => HostedIrqArenaError::Poisoned,
                LANE_SHUTDOWN => HostedIrqArenaError::Shutdown,
                _ => HostedIrqArenaError::NotReady,
            })
    }

    pub fn root_begin_transaction(
        &self,
        identity: HostedIrqLaneIdentity,
        class: HostedIrqTransactionClass,
    ) -> Result<HostedIrqTransaction, HostedIrqArenaError> {
        self.check_identity(identity)?;
        self.check_lane_active()?;
        if self.current_irql.load(Ordering::Acquire) != 0 {
            return Err(HostedIrqArenaError::InvalidIrql);
        }
        self.active_transaction
            .compare_exchange(
                0,
                TRANSACTION_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqArenaError::Busy)?;
        if let Err(error) = self.check_lane_active() {
            self.active_transaction.store(0, Ordering::Release);
            return Err(error);
        }
        let transaction = match self
            .transaction_next
            .load(Ordering::Relaxed)
            .checked_add(1)
            .filter(|transaction| *transaction != TRANSACTION_PUBLISHING)
        {
            Some(transaction) => transaction,
            None => {
                self.active_transaction.store(0, Ordering::Release);
                let _ = self.record_first_fault(
                    identity,
                    HostedIrqFaultRecord {
                        kind: HostedIrqFaultKind::Protocol,
                        transaction: 0,
                        sequence: u64::MAX,
                        depth: 0,
                        direction: HostedIrqLaneDirection::Dispatch,
                        code: 1,
                        instruction_pointer: 0,
                        address: 0,
                        parameters: [0; 4],
                    },
                );
                return Err(HostedIrqArenaError::SequenceExhausted);
            }
        };
        self.transaction_next.store(transaction, Ordering::Relaxed);
        self.active_transaction_class
            .store(class as u32, Ordering::Relaxed);
        self.active_transaction
            .store(transaction, Ordering::Release);
        Ok(HostedIrqTransaction {
            lane_generation: identity.lane_generation,
            transaction,
            class,
        })
    }

    fn check_transaction_present(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_identity(identity)?;
        if transaction.lane_generation != identity.lane_generation
            || transaction.transaction == 0
            || transaction.transaction == TRANSACTION_PUBLISHING
            || self.active_transaction.load(Ordering::Acquire) != transaction.transaction
            || self.active_transaction_class.load(Ordering::Acquire) != transaction.class as u32
        {
            return Err(HostedIrqArenaError::StaleTransaction);
        }
        Ok(())
    }

    fn check_transaction(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_transaction_present(identity, transaction)?;
        self.check_lane_active()
    }

    pub fn root_finish_transaction(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_transaction_present(identity, transaction)?;
        self.active_transaction
            .compare_exchange(
                transaction.transaction,
                TRANSACTION_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqArenaError::StaleTransaction)?;
        if self.dispatch_mask.load(Ordering::Acquire) != 0
            || self.service_mask.load(Ordering::Acquire) != 0
            || self.dispatch_running_mask.load(Ordering::Acquire) != 0
            || self.service_running_mask.load(Ordering::Acquire) != 0
        {
            self.active_transaction
                .store(transaction.transaction, Ordering::Release);
            return Err(HostedIrqArenaError::Busy);
        }
        if self.current_irql.load(Ordering::Acquire) != 0 {
            self.active_transaction
                .store(transaction.transaction, Ordering::Release);
            return Err(HostedIrqArenaError::InvalidIrql);
        }
        self.active_transaction_class.store(0, Ordering::Release);
        self.active_transaction.store(0, Ordering::Release);
        Ok(())
    }

    /// Recover the exact active transaction class for a token received by the lane worker.
    /// Nested dispatch kinds do not define a new transaction: provider callbacks inherit the
    /// Interrupt, Dpc, or Callback transaction opened by the root.
    pub fn active_transaction(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: u64,
    ) -> Result<HostedIrqTransaction, HostedIrqArenaError> {
        self.check_identity(identity)?;
        let class = HostedIrqTransactionClass::from_raw(
            self.active_transaction_class.load(Ordering::Acquire),
        )
        .ok_or(HostedIrqArenaError::StaleTransaction)?;
        let active = HostedIrqTransaction {
            lane_generation: identity.lane_generation,
            transaction,
            class,
        };
        self.check_transaction_present(identity, active)?;
        Ok(active)
    }

    pub fn current_irql(&self, identity: HostedIrqLaneIdentity) -> Result<u8, HostedIrqArenaError> {
        self.check_identity(identity)?;
        Ok(self.current_irql.load(Ordering::Acquire) as u8)
    }

    pub fn worker_raise_irql(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
        expected: u8,
        target: u8,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_transaction(identity, transaction)?;
        if target > self.high_irql as u8 || target < expected {
            return Err(HostedIrqArenaError::InvalidIrql);
        }
        self.current_irql
            .compare_exchange(
                expected as u32,
                target as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| HostedIrqArenaError::InvalidIrql)
    }

    pub fn worker_lower_irql(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
        expected: u8,
        target: u8,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_transaction_present(identity, transaction)?;
        if expected > self.high_irql as u8 || target > expected {
            return Err(HostedIrqArenaError::InvalidIrql);
        }
        self.current_irql
            .compare_exchange(
                expected as u32,
                target as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| HostedIrqArenaError::InvalidIrql)
    }

    fn direction_mask(&self, direction: HostedIrqLaneDirection) -> &AtomicU32 {
        match direction {
            HostedIrqLaneDirection::Dispatch => &self.dispatch_mask,
            HostedIrqLaneDirection::Service => &self.service_mask,
        }
    }

    fn direction_running_mask(&self, direction: HostedIrqLaneDirection) -> &AtomicU32 {
        match direction {
            HostedIrqLaneDirection::Dispatch => &self.dispatch_running_mask,
            HostedIrqLaneDirection::Service => &self.service_running_mask,
        }
    }

    fn claim(
        &self,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
        direction: HostedIrqLaneDirection,
        depth: u8,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_transaction_present(identity, transaction)?;
        let depth = depth as usize;
        if depth >= HOSTED_IRQ_ARENA_DEPTH {
            return Err(HostedIrqArenaError::InvalidDepth);
        }
        let bit = 1u32 << depth;
        let dispatches = self.dispatch_mask.load(Ordering::Acquire);
        let services = self.service_mask.load(Ordering::Acquire);
        let running_dispatches = self.dispatch_running_mask.load(Ordering::Acquire);
        let running_services = self.service_running_mask.load(Ordering::Acquire);
        match direction {
            HostedIrqLaneDirection::Dispatch => {
                let deeper = !((1u32 << depth) - 1);
                if dispatches & deeper != 0 || services & deeper != 0 {
                    return Err(HostedIrqArenaError::NestingViolation);
                }
                if depth != 0 && running_services & (1u32 << (depth - 1)) == 0 {
                    return Err(HostedIrqArenaError::NestingViolation);
                }
            }
            HostedIrqLaneDirection::Service => {
                let deeper_dispatch = !((1u32 << (depth + 1)) - 1);
                let same_or_deeper_service = !((1u32 << depth) - 1);
                if running_dispatches & bit == 0
                    || dispatches & deeper_dispatch != 0
                    || services & same_or_deeper_service != 0
                {
                    return Err(HostedIrqArenaError::NestingViolation);
                }
            }
        }
        self.direction_mask(direction)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
                (mask & bit == 0).then_some(mask | bit)
            })
            .map_err(|_| HostedIrqArenaError::Busy)?;
        if let Err(error) = self.check_transaction(identity, transaction) {
            self.cancel_claim(direction, depth as u8);
            return Err(error);
        }
        let observed_depth = depth as u32 + 1;
        self.depth_high_water
            .fetch_max(observed_depth, Ordering::Relaxed);
        Ok(())
    }

    fn cancel_claim(&self, direction: HostedIrqLaneDirection, depth: u8) {
        self.direction_mask(direction)
            .fetch_and(!(1u32 << depth), Ordering::AcqRel);
    }

    fn mark_running(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.token_is_active(identity, token)?;
        let bit = 1u32 << token.depth;
        self.direction_running_mask(token.direction)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
                (mask & bit == 0).then_some(mask | bit)
            })
            .map_err(|_| HostedIrqArenaError::Busy)?;
        if let Err(error) = self.token_is_active(identity, token) {
            self.direction_running_mask(token.direction)
                .fetch_and(!bit, Ordering::AcqRel);
            return Err(error);
        }
        Ok(())
    }

    fn pause_running(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.token_is_active(identity, token)?;
        let bit = 1u32 << token.depth;
        self.direction_running_mask(token.direction)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
                (mask & bit != 0).then_some(mask & !bit)
            })
            .map(|_| ())
            .map_err(|_| HostedIrqArenaError::NotRunning)
    }

    fn resume_running(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.token_is_active(identity, token)?;
        let bit = 1u32 << token.depth;
        self.direction_running_mask(token.direction)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
                (mask & bit == 0).then_some(mask | bit)
            })
            .map(|_| ())
            .map_err(|_| HostedIrqArenaError::Busy)
    }

    fn release(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        let transaction = HostedIrqTransaction {
            lane_generation: token.lane_generation,
            transaction: token.transaction,
            class: HostedIrqTransactionClass::from_raw(
                self.active_transaction_class.load(Ordering::Acquire),
            )
            .ok_or(HostedIrqArenaError::StaleTransaction)?,
        };
        self.check_transaction_present(identity, transaction)?;
        self.can_release(identity, token)?;
        let bit = 1u32 << token.depth;
        self.direction_mask(token.direction)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
                (mask & bit != 0).then_some(mask & !bit)
            })
            .map(|_| ())
            .map_err(|_| HostedIrqArenaError::StaleToken)
    }

    fn can_close(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.token_is_active(identity, token)?;
        let depth = token.depth as usize;
        let bit = 1u32 << depth;
        let dispatches = self.dispatch_mask.load(Ordering::Acquire);
        let services = self.service_mask.load(Ordering::Acquire);
        match token.direction {
            HostedIrqLaneDirection::Dispatch => {
                let deeper = !((1u32 << depth) - 1);
                if dispatches & bit == 0
                    || dispatches & (deeper & !bit) != 0
                    || services & deeper != 0
                {
                    return Err(HostedIrqArenaError::NestingViolation);
                }
            }
            HostedIrqLaneDirection::Service => {
                let deeper = !((1u32 << (depth + 1)) - 1);
                if services & bit == 0 || dispatches & deeper != 0 || services & deeper != 0 {
                    return Err(HostedIrqArenaError::NestingViolation);
                }
            }
        }
        Ok(())
    }

    fn can_release(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.can_close(identity, token)?;
        if self
            .direction_running_mask(token.direction)
            .load(Ordering::Acquire)
            & (1u32 << token.depth)
            != 0
        {
            return Err(HostedIrqArenaError::NotRunning);
        }
        Ok(())
    }

    fn token_is_active(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        if !token.valid() || token.lane_generation != identity.lane_generation {
            return Err(HostedIrqArenaError::StaleToken);
        }
        let class = HostedIrqTransactionClass::from_raw(
            self.active_transaction_class.load(Ordering::Acquire),
        )
        .ok_or(HostedIrqArenaError::StaleTransaction)?;
        self.check_transaction_present(
            identity,
            HostedIrqTransaction {
                lane_generation: token.lane_generation,
                transaction: token.transaction,
                class,
            },
        )?;
        let bit = 1u32 << token.depth;
        if self.direction_mask(token.direction).load(Ordering::Acquire) & bit == 0 {
            return Err(HostedIrqArenaError::StaleToken);
        }
        Ok(())
    }

    fn poison_lane(&self) -> Result<(), HostedIrqArenaError> {
        self.lane_state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                matches!(
                    state,
                    LANE_BOOTING | LANE_READY | LANE_ACTIVE | LANE_POISONED
                )
                .then_some(LANE_POISONED)
            })
            .map(|_| ())
            .map_err(|state| match state {
                LANE_SHUTDOWN => HostedIrqArenaError::Shutdown,
                _ => HostedIrqArenaError::NotReady,
            })
    }

    pub fn record_first_fault(
        &self,
        identity: HostedIrqLaneIdentity,
        fault: HostedIrqFaultRecord,
    ) -> Result<bool, HostedIrqArenaError> {
        self.check_identity(identity)?;
        if !fault.valid() || fault.kind == HostedIrqFaultKind::BugCheck {
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        if self.lane_state.load(Ordering::Acquire) == LANE_SHUTDOWN {
            return Err(HostedIrqArenaError::Shutdown);
        }
        if self
            .fault_state
            .compare_exchange(
                FAULT_EMPTY,
                FAULT_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.poison_lane()?;
            return Ok(false);
        }
        if let Err(error) = self.poison_lane() {
            let _ = self.fault_state.compare_exchange(
                FAULT_PUBLISHING,
                FAULT_EMPTY,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(error);
        }
        self.fault_kind.store(fault.kind as u32, Ordering::Relaxed);
        self.fault_transaction
            .store(fault.transaction, Ordering::Relaxed);
        self.fault_sequence.store(fault.sequence, Ordering::Relaxed);
        self.fault_depth_direction.store(
            fault.depth as u32 | (fault.direction as u32) << 8,
            Ordering::Relaxed,
        );
        self.fault_code.store(fault.code, Ordering::Relaxed);
        self.fault_instruction_pointer
            .store(fault.instruction_pointer, Ordering::Relaxed);
        self.fault_address.store(fault.address, Ordering::Relaxed);
        for (slot, value) in self.fault_parameters.iter().zip(fault.parameters) {
            slot.store(value, Ordering::Relaxed);
        }
        self.fault_state.store(FAULT_RECORDED, Ordering::Release);
        Ok(true)
    }

    pub fn first_fault(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<Option<HostedIrqFaultRecord>, HostedIrqArenaError> {
        self.check_identity(identity)?;
        if self.fault_state.load(Ordering::Acquire) != FAULT_RECORDED {
            return Ok(None);
        }
        let depth_direction = self.fault_depth_direction.load(Ordering::Relaxed);
        let Some(kind) = HostedIrqFaultKind::from_raw(self.fault_kind.load(Ordering::Relaxed))
        else {
            return Err(HostedIrqArenaError::InvalidLayout);
        };
        let Some(direction) = HostedIrqLaneDirection::from_raw(depth_direction >> 8) else {
            return Err(HostedIrqArenaError::InvalidLayout);
        };
        let fault = HostedIrqFaultRecord {
            kind,
            transaction: self.fault_transaction.load(Ordering::Relaxed),
            sequence: self.fault_sequence.load(Ordering::Relaxed),
            depth: depth_direction as u8,
            direction,
            code: self.fault_code.load(Ordering::Relaxed),
            instruction_pointer: self.fault_instruction_pointer.load(Ordering::Relaxed),
            address: self.fault_address.load(Ordering::Relaxed),
            parameters: core::array::from_fn(|index| {
                self.fault_parameters[index].load(Ordering::Relaxed)
            }),
        };
        if !fault.valid() || fault.kind == HostedIrqFaultKind::BugCheck {
            return Err(HostedIrqArenaError::InvalidLayout);
        }
        Ok(Some(fault))
    }

    pub fn record_first_bugcheck(
        &self,
        identity: HostedIrqLaneIdentity,
        bugcheck: HostedIrqFaultRecord,
    ) -> Result<bool, HostedIrqArenaError> {
        self.check_identity(identity)?;
        if !bugcheck.valid() || bugcheck.kind != HostedIrqFaultKind::BugCheck {
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        if self.lane_state.load(Ordering::Acquire) == LANE_SHUTDOWN {
            return Err(HostedIrqArenaError::Shutdown);
        }
        if self
            .bugcheck_state
            .compare_exchange(
                FAULT_EMPTY,
                FAULT_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.poison_lane()?;
            return Ok(false);
        }
        if let Err(error) = self.poison_lane() {
            let _ = self.bugcheck_state.compare_exchange(
                FAULT_PUBLISHING,
                FAULT_EMPTY,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(error);
        }
        self.bugcheck_transaction
            .store(bugcheck.transaction, Ordering::Relaxed);
        self.bugcheck_sequence
            .store(bugcheck.sequence, Ordering::Relaxed);
        self.bugcheck_depth_direction.store(
            bugcheck.depth as u32 | (bugcheck.direction as u32) << 8,
            Ordering::Relaxed,
        );
        self.bugcheck_code.store(bugcheck.code, Ordering::Relaxed);
        self.bugcheck_instruction_pointer
            .store(bugcheck.instruction_pointer, Ordering::Relaxed);
        self.bugcheck_address
            .store(bugcheck.address, Ordering::Relaxed);
        for (slot, value) in self.bugcheck_parameters.iter().zip(bugcheck.parameters) {
            slot.store(value, Ordering::Relaxed);
        }
        self.bugcheck_state.store(FAULT_RECORDED, Ordering::Release);
        Ok(true)
    }

    pub fn first_bugcheck(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<Option<HostedIrqFaultRecord>, HostedIrqArenaError> {
        self.check_identity(identity)?;
        if self.bugcheck_state.load(Ordering::Acquire) != FAULT_RECORDED {
            return Ok(None);
        }
        let depth_direction = self.bugcheck_depth_direction.load(Ordering::Relaxed);
        let Some(direction) = HostedIrqLaneDirection::from_raw(depth_direction >> 8) else {
            return Err(HostedIrqArenaError::InvalidLayout);
        };
        let bugcheck = HostedIrqFaultRecord {
            kind: HostedIrqFaultKind::BugCheck,
            transaction: self.bugcheck_transaction.load(Ordering::Relaxed),
            sequence: self.bugcheck_sequence.load(Ordering::Relaxed),
            depth: depth_direction as u8,
            direction,
            code: self.bugcheck_code.load(Ordering::Relaxed),
            instruction_pointer: self.bugcheck_instruction_pointer.load(Ordering::Relaxed),
            address: self.bugcheck_address.load(Ordering::Relaxed),
            parameters: core::array::from_fn(|index| {
                self.bugcheck_parameters[index].load(Ordering::Relaxed)
            }),
        };
        if !bugcheck.valid() || bugcheck.kind != HostedIrqFaultKind::BugCheck {
            return Err(HostedIrqArenaError::InvalidLayout);
        }
        Ok(Some(bugcheck))
    }

    pub fn depth_high_water(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<u8, HostedIrqArenaError> {
        self.check_identity(identity)?;
        Ok(self.depth_high_water.load(Ordering::Acquire) as u8)
    }

    pub fn root_request_shutdown(
        &self,
        identity: HostedIrqLaneIdentity,
    ) -> Result<(), HostedIrqArenaError> {
        self.check_identity(identity)?;
        if self.active_transaction.load(Ordering::Acquire) != 0
            || self.dispatch_mask.load(Ordering::Acquire) != 0
            || self.service_mask.load(Ordering::Acquire) != 0
            || self.dispatch_running_mask.load(Ordering::Acquire) != 0
            || self.service_running_mask.load(Ordering::Acquire) != 0
            || self.current_irql.load(Ordering::Acquire) != 0
            || self.fault_state.load(Ordering::Acquire) == FAULT_PUBLISHING
            || self.bugcheck_state.load(Ordering::Acquire) == FAULT_PUBLISHING
        {
            return Err(HostedIrqArenaError::Busy);
        }
        self.lane_state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (matches!(state, LANE_READY | LANE_ACTIVE | LANE_POISONED)
                    && self.fault_state.load(Ordering::Acquire) != FAULT_PUBLISHING
                    && self.bugcheck_state.load(Ordering::Acquire) != FAULT_PUBLISHING)
                    .then_some(LANE_SHUTDOWN)
            })
            .map(|_| ())
            .map_err(|state| match state {
                LANE_POISONED
                    if self.fault_state.load(Ordering::Acquire) == FAULT_PUBLISHING
                        || self.bugcheck_state.load(Ordering::Acquire) == FAULT_PUBLISHING =>
                {
                    HostedIrqArenaError::Busy
                }
                LANE_SHUTDOWN => HostedIrqArenaError::Shutdown,
                _ => HostedIrqArenaError::NotReady,
            })
    }
}

#[repr(C, align(4096))]
struct HostedIrqSlotPage {
    magic: u64,
    version: u16,
    size: u16,
    direction: u16,
    reserved: u16,
    domain_id: u64,
    domain_cookie: u64,
    lane_generation: u64,
    state: AtomicU32,
    depth: AtomicU32,
    transaction: AtomicU64,
    sequence: AtomicU64,
    kind: AtomicU32,
    argument_count: AtomicU32,
    operation: AtomicU64,
    target0: AtomicU64,
    target1: AtomicU64,
    context: AtomicU64,
    irql: AtomicU32,
    result_value_count: AtomicU32,
    grant_owner_domain_id: AtomicU64,
    grant_owner_domain_cookie: AtomicU64,
    grant_id: AtomicU64,
    grant_generation: AtomicU64,
    arguments: [AtomicU64; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
    result_status: AtomicI32,
    result_faulted: AtomicU32,
    result_values: [AtomicU64; HOSTED_IRQ_ARENA_RESULT_CAP],
    padding: [u8; 3816],
}

#[derive(Clone, Copy)]
struct HostedIrqWireCommand {
    kind: u32,
    argument_count: u32,
    operation: u64,
    target0: u64,
    target1: u64,
    context: u64,
    irql: u32,
    grant: HostedIrqGrantIdentity,
    arguments: [u64; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
}

impl HostedIrqSlotPage {
    fn new(identity: HostedIrqLaneIdentity, direction: HostedIrqLaneDirection) -> Self {
        Self {
            magic: HOSTED_IRQ_ARENA_MAGIC,
            version: HOSTED_IRQ_ARENA_VERSION,
            size: core::mem::size_of::<Self>() as u16,
            direction: direction as u16,
            reserved: 0,
            domain_id: identity.domain_id,
            domain_cookie: identity.domain_cookie,
            lane_generation: identity.lane_generation,
            state: AtomicU32::new(SLOT_IDLE),
            depth: AtomicU32::new(0),
            transaction: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            kind: AtomicU32::new(0),
            argument_count: AtomicU32::new(0),
            operation: AtomicU64::new(0),
            target0: AtomicU64::new(0),
            target1: AtomicU64::new(0),
            context: AtomicU64::new(0),
            irql: AtomicU32::new(0),
            result_value_count: AtomicU32::new(0),
            grant_owner_domain_id: AtomicU64::new(0),
            grant_owner_domain_cookie: AtomicU64::new(0),
            grant_id: AtomicU64::new(0),
            grant_generation: AtomicU64::new(0),
            arguments: [const { AtomicU64::new(0) }; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
            result_status: AtomicI32::new(0),
            result_faulted: AtomicU32::new(0),
            result_values: [const { AtomicU64::new(0) }; HOSTED_IRQ_ARENA_RESULT_CAP],
            padding: [0; 3816],
        }
    }

    fn identity(&self) -> Option<HostedIrqLaneIdentity> {
        if self.magic != HOSTED_IRQ_ARENA_MAGIC
            || self.version != HOSTED_IRQ_ARENA_VERSION
            || self.size as usize != core::mem::size_of::<Self>()
            || HostedIrqLaneDirection::from_raw(self.direction as u32).is_none()
        {
            return None;
        }
        HostedIrqLaneIdentity::new(self.domain_id, self.domain_cookie, self.lane_generation)
    }

    fn check(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        direction: HostedIrqLaneDirection,
    ) -> Result<(), HostedIrqArenaError> {
        control.check_identity(identity)?;
        if self.identity() != Some(identity) || self.direction as u32 != direction as u32 {
            return Err(HostedIrqArenaError::InvalidIdentity);
        }
        Ok(())
    }

    fn publish(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
        direction: HostedIrqLaneDirection,
        depth: u8,
        command: HostedIrqWireCommand,
    ) -> Result<HostedIrqArenaToken, HostedIrqArenaError> {
        self.check(control, identity, direction)?;
        self.state
            .compare_exchange(
                SLOT_IDLE,
                SLOT_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqArenaError::Busy)?;
        if let Err(error) = control.claim(identity, transaction, direction, depth) {
            self.state.store(SLOT_IDLE, Ordering::Release);
            return Err(error);
        }
        let sequence = match self
            .sequence
            .load(Ordering::Relaxed)
            .checked_add(1)
            .filter(|sequence| *sequence != 0)
        {
            Some(sequence) => sequence,
            None => {
                control.cancel_claim(direction, depth);
                self.state.store(SLOT_IDLE, Ordering::Release);
                let _ = control.record_first_fault(
                    identity,
                    HostedIrqFaultRecord {
                        kind: HostedIrqFaultKind::Protocol,
                        transaction: transaction.transaction,
                        sequence: u64::MAX,
                        depth,
                        direction,
                        code: 2,
                        instruction_pointer: 0,
                        address: 0,
                        parameters: [0; 4],
                    },
                );
                return Err(HostedIrqArenaError::SequenceExhausted);
            }
        };
        self.depth.store(depth as u32, Ordering::Relaxed);
        self.transaction
            .store(transaction.transaction, Ordering::Relaxed);
        self.kind.store(command.kind, Ordering::Relaxed);
        self.argument_count
            .store(command.argument_count as u32, Ordering::Relaxed);
        self.operation.store(command.operation, Ordering::Relaxed);
        self.target0.store(command.target0, Ordering::Relaxed);
        self.target1.store(command.target1, Ordering::Relaxed);
        self.context.store(command.context, Ordering::Relaxed);
        self.irql.store(command.irql, Ordering::Relaxed);
        self.grant_owner_domain_id
            .store(command.grant.owner_domain_id, Ordering::Relaxed);
        self.grant_owner_domain_cookie
            .store(command.grant.owner_domain_cookie, Ordering::Relaxed);
        self.grant_id
            .store(command.grant.grant_id, Ordering::Relaxed);
        self.grant_generation
            .store(command.grant.grant_generation, Ordering::Relaxed);
        for (slot, value) in self.arguments.iter().zip(command.arguments) {
            slot.store(value, Ordering::Relaxed);
        }
        self.result_status.store(0, Ordering::Relaxed);
        self.result_faulted.store(0, Ordering::Relaxed);
        self.result_value_count.store(0, Ordering::Relaxed);
        for slot in &self.result_values {
            slot.store(0, Ordering::Relaxed);
        }
        self.sequence.store(sequence, Ordering::Relaxed);
        self.state.store(SLOT_PENDING, Ordering::Release);
        Ok(HostedIrqArenaToken {
            lane_generation: identity.lane_generation,
            transaction: transaction.transaction,
            sequence,
            depth,
            direction,
        })
    }

    fn validate_token(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        direction: HostedIrqLaneDirection,
    ) -> Result<(), HostedIrqArenaError> {
        if !token.valid()
            || token.direction != direction
            || token.lane_generation != identity.lane_generation
            || self.transaction.load(Ordering::Acquire) != token.transaction
            || self.sequence.load(Ordering::Acquire) != token.sequence
            || self.depth.load(Ordering::Acquire) != token.depth as u32
        {
            return Err(HostedIrqArenaError::StaleToken);
        }
        Ok(())
    }

    fn begin(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        direction: HostedIrqLaneDirection,
    ) -> Result<HostedIrqWireCommand, HostedIrqArenaError> {
        self.check(control, identity, direction)?;
        control.token_is_active(identity, token)?;
        self.validate_token(identity, token, direction)?;
        if self.state.load(Ordering::Acquire) != SLOT_PENDING {
            return Err(HostedIrqArenaError::NotPending);
        }
        let command = HostedIrqWireCommand {
            kind: self.kind.load(Ordering::Relaxed),
            argument_count: self.argument_count.load(Ordering::Relaxed),
            operation: self.operation.load(Ordering::Relaxed),
            target0: self.target0.load(Ordering::Relaxed),
            target1: self.target1.load(Ordering::Relaxed),
            context: self.context.load(Ordering::Relaxed),
            irql: self.irql.load(Ordering::Relaxed),
            grant: HostedIrqGrantIdentity {
                owner_domain_id: self.grant_owner_domain_id.load(Ordering::Relaxed),
                owner_domain_cookie: self.grant_owner_domain_cookie.load(Ordering::Relaxed),
                grant_id: self.grant_id.load(Ordering::Relaxed),
                grant_generation: self.grant_generation.load(Ordering::Relaxed),
            },
            arguments: core::array::from_fn(|index| self.arguments[index].load(Ordering::Relaxed)),
        };
        if !Self::wire_command_valid(control, identity, token, direction, command) {
            let fault_kind = if direction == HostedIrqLaneDirection::Service {
                HostedIrqFaultKind::ServiceFault
            } else {
                HostedIrqFaultKind::Protocol
            };
            let _ = control.record_first_fault(
                identity,
                HostedIrqFaultRecord {
                    kind: fault_kind,
                    transaction: token.transaction,
                    sequence: token.sequence,
                    depth: token.depth,
                    direction,
                    code: 3,
                    instruction_pointer: 0,
                    address: 0,
                    parameters: [0; 4],
                },
            );
            self.abort_pending(control, identity, token)?;
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        self.state
            .compare_exchange(
                SLOT_PENDING,
                SLOT_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqArenaError::NotPending)?;
        if let Err(error) = control.mark_running(identity, token) {
            let _ = self.state.compare_exchange(
                SLOT_RUNNING,
                SLOT_PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(error);
        }
        Ok(command)
    }

    fn abort_pending(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.state
            .compare_exchange(
                SLOT_PENDING,
                SLOT_RELEASING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqArenaError::NotPending)?;
        if let Err(error) = control.release(identity, token) {
            let _ = self.state.compare_exchange(
                SLOT_RELEASING,
                SLOT_PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(error);
        }
        self.state.store(SLOT_IDLE, Ordering::Release);
        Ok(())
    }

    fn wire_command_valid(
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        direction: HostedIrqLaneDirection,
        wire: HostedIrqWireCommand,
    ) -> bool {
        match direction {
            HostedIrqLaneDirection::Dispatch => {
                if wire.argument_count > HOSTED_IRQ_ARENA_ARGUMENT_CAP as u32
                    || wire.irql & !0xffff != 0
                {
                    return false;
                }
                let Some(kind) = HostedIrqDispatchKind::from_raw(wire.kind) else {
                    return false;
                };
                let command = HostedIrqDispatchCommand {
                    kind,
                    work_id: wire.operation,
                    routine: wire.target0,
                    object: wire.target1,
                    context: wire.context,
                    entry_irql: wire.irql as u8,
                    synchronize_irql: (wire.irql >> 8) as u8,
                    grant: wire.grant,
                    argument_count: wire.argument_count as u8,
                    arguments: wire.arguments,
                };
                let Some(class) = HostedIrqTransactionClass::from_raw(
                    control.active_transaction_class.load(Ordering::Acquire),
                ) else {
                    return false;
                };
                command.valid()
                    && command.grant.owner_domain_id == identity.domain_id
                    && command.grant.owner_domain_cookie == identity.domain_cookie
                    && command.entry_irql <= control.high_irql as u8
                    && command.synchronize_irql <= control.high_irql as u8
                    && (kind != HostedIrqDispatchKind::InterruptService
                        || class == HostedIrqTransactionClass::Interrupt)
                    && (kind != HostedIrqDispatchKind::DeferredProcedure
                        || (class == HostedIrqTransactionClass::Dpc && token.depth == 0))
            }
            HostedIrqLaneDirection::Service => {
                if wire.argument_count > HOSTED_IRQ_ARENA_ARGUMENT_CAP as u32 {
                    return false;
                }
                let Some(kind) = HostedIrqServiceKind::from_raw(wire.kind) else {
                    return false;
                };
                HostedIrqServiceCommand {
                    kind,
                    service_id: wire.operation,
                    target_domain_id: wire.target0,
                    target_domain_cookie: wire.target1,
                    grant: wire.grant,
                    argument_count: wire.argument_count as u8,
                    arguments: wire.arguments,
                }
                .valid()
                    && wire.grant.owner_domain_id == identity.domain_id
                    && wire.grant.owner_domain_cookie == identity.domain_cookie
            }
        }
    }

    fn complete(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        direction: HostedIrqLaneDirection,
        result: HostedIrqArenaResult,
    ) -> Result<(), HostedIrqArenaError> {
        self.check(control, identity, direction)?;
        self.validate_token(identity, token, direction)?;
        if !result.valid() {
            return Err(HostedIrqArenaError::InvalidResult);
        }
        self.state
            .compare_exchange(
                SLOT_RUNNING,
                SLOT_COMPLETING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HostedIrqArenaError::NotRunning)?;
        if let Err(error) = control.pause_running(identity, token) {
            let _ = self.state.compare_exchange(
                SLOT_COMPLETING,
                SLOT_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(error);
        }
        if let Err(error) = control.can_close(identity, token) {
            let resume = control.resume_running(identity, token);
            let restore = self.state.compare_exchange(
                SLOT_COMPLETING,
                SLOT_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if let Err(resume_error) = resume {
                let _ = control.record_first_fault(
                    identity,
                    HostedIrqFaultRecord {
                        kind: HostedIrqFaultKind::Protocol,
                        transaction: token.transaction,
                        sequence: token.sequence,
                        depth: token.depth,
                        direction,
                        code: 4,
                        instruction_pointer: 0,
                        address: 0,
                        parameters: [0; 4],
                    },
                );
                return Err(resume_error);
            }
            if restore.is_err() {
                let _ = control.record_first_fault(
                    identity,
                    HostedIrqFaultRecord {
                        kind: HostedIrqFaultKind::Protocol,
                        transaction: token.transaction,
                        sequence: token.sequence,
                        depth: token.depth,
                        direction,
                        code: 5,
                        instruction_pointer: 0,
                        address: 0,
                        parameters: [0; 4],
                    },
                );
                return Err(HostedIrqArenaError::NotRunning);
            }
            return Err(error);
        }
        self.result_status.store(result.status, Ordering::Relaxed);
        self.result_faulted
            .store(result.faulted as u32, Ordering::Relaxed);
        self.result_value_count
            .store(result.value_count as u32, Ordering::Relaxed);
        for (slot, value) in self.result_values.iter().zip(result.values) {
            slot.store(value, Ordering::Relaxed);
        }
        self.state.store(
            if result.faulted {
                SLOT_FAULTED
            } else {
                SLOT_COMPLETE
            },
            Ordering::Release,
        );
        Ok(())
    }

    fn completion(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        direction: HostedIrqLaneDirection,
    ) -> Result<HostedIrqArenaResult, HostedIrqArenaError> {
        if self.identity() != Some(identity) {
            return Err(HostedIrqArenaError::InvalidIdentity);
        }
        self.validate_token(identity, token, direction)?;
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, SLOT_COMPLETE | SLOT_FAULTED) {
            return Err(HostedIrqArenaError::ResultNotReady);
        }
        let raw_value_count = self.result_value_count.load(Ordering::Relaxed);
        if raw_value_count > HOSTED_IRQ_ARENA_RESULT_CAP as u32 {
            return Err(HostedIrqArenaError::InvalidResult);
        }
        let value_count = raw_value_count as u8;
        Ok(HostedIrqArenaResult {
            status: self.result_status.load(Ordering::Relaxed),
            faulted: state == SLOT_FAULTED,
            value_count,
            values: core::array::from_fn(|index| self.result_values[index].load(Ordering::Relaxed)),
        })
    }

    fn acknowledge(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        direction: HostedIrqLaneDirection,
    ) -> Result<(), HostedIrqArenaError> {
        self.check(control, identity, direction)?;
        control.token_is_active(identity, token)?;
        self.validate_token(identity, token, direction)?;
        let terminal_state = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                matches!(state, SLOT_COMPLETE | SLOT_FAULTED).then_some(SLOT_RELEASING)
            })
            .map_err(|_| HostedIrqArenaError::ResultNotReady)?;
        if let Err(error) = control.release(identity, token) {
            let _ = self.state.compare_exchange(
                SLOT_RELEASING,
                terminal_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(error);
        }
        self.state.store(SLOT_IDLE, Ordering::Release);
        Ok(())
    }
}

/// One executive-to-lane command page at a fixed nesting depth.
#[repr(C, align(4096))]
pub struct HostedIrqDispatchPage(HostedIrqSlotPage);

impl HostedIrqDispatchPage {
    pub fn new(identity: HostedIrqLaneIdentity) -> Self {
        Self(HostedIrqSlotPage::new(
            identity,
            HostedIrqLaneDirection::Dispatch,
        ))
    }

    pub fn root_publish(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
        depth: u8,
        command: HostedIrqDispatchCommand,
    ) -> Result<HostedIrqArenaToken, HostedIrqArenaError> {
        if !command.valid() {
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        if command.grant.owner_domain_id != identity.domain_id
            || command.grant.owner_domain_cookie != identity.domain_cookie
            || command.entry_irql > control.high_irql as u8
            || command.synchronize_irql > control.high_irql as u8
            || (command.kind == HostedIrqDispatchKind::InterruptService
                && transaction.class != HostedIrqTransactionClass::Interrupt)
            || (command.kind == HostedIrqDispatchKind::DeferredProcedure
                && (transaction.class != HostedIrqTransactionClass::Dpc || depth != 0))
        {
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        self.0.publish(
            control,
            identity,
            transaction,
            HostedIrqLaneDirection::Dispatch,
            depth,
            HostedIrqWireCommand {
                kind: command.kind as u32,
                argument_count: command.argument_count as u32,
                operation: command.work_id,
                target0: command.routine,
                target1: command.object,
                context: command.context,
                irql: command.entry_irql as u32 | (command.synchronize_irql as u32) << 8,
                grant: command.grant,
                arguments: command.arguments,
            },
        )
    }

    pub fn worker_begin(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<HostedIrqDispatchCommand, HostedIrqArenaError> {
        let wire = self
            .0
            .begin(control, identity, token, HostedIrqLaneDirection::Dispatch)?;
        let Some(kind) = HostedIrqDispatchKind::from_raw(wire.kind) else {
            return Err(HostedIrqArenaError::InvalidCommand);
        };
        let command = HostedIrqDispatchCommand {
            kind,
            work_id: wire.operation,
            routine: wire.target0,
            object: wire.target1,
            context: wire.context,
            entry_irql: wire.irql as u8,
            synchronize_irql: (wire.irql >> 8) as u8,
            grant: wire.grant,
            argument_count: wire.argument_count as u8,
            arguments: wire.arguments,
        };
        if command.valid() {
            if command.grant.owner_domain_id == identity.domain_id
                && command.grant.owner_domain_cookie == identity.domain_cookie
                && command.entry_irql <= control.high_irql as u8
                && command.synchronize_irql <= control.high_irql as u8
            {
                Ok(command)
            } else {
                Err(HostedIrqArenaError::InvalidCommand)
            }
        } else {
            Err(HostedIrqArenaError::InvalidCommand)
        }
    }

    pub fn worker_complete(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        result: HostedIrqArenaResult,
    ) -> Result<(), HostedIrqArenaError> {
        self.0.complete(
            control,
            identity,
            token,
            HostedIrqLaneDirection::Dispatch,
            result,
        )
    }

    pub fn root_completion(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<HostedIrqArenaResult, HostedIrqArenaError> {
        self.0
            .completion(identity, token, HostedIrqLaneDirection::Dispatch)
    }

    pub fn root_acknowledge(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.0
            .acknowledge(control, identity, token, HostedIrqLaneDirection::Dispatch)
    }
}

/// One lane-to-executive service page at a fixed nesting depth.
#[repr(C, align(4096))]
pub struct HostedIrqServicePage(HostedIrqSlotPage);

impl HostedIrqServicePage {
    pub fn new(identity: HostedIrqLaneIdentity) -> Self {
        Self(HostedIrqSlotPage::new(
            identity,
            HostedIrqLaneDirection::Service,
        ))
    }

    pub fn worker_publish(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        transaction: HostedIrqTransaction,
        depth: u8,
        command: HostedIrqServiceCommand,
    ) -> Result<HostedIrqArenaToken, HostedIrqArenaError> {
        if !command.valid() {
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        if command.grant.owner_domain_id != identity.domain_id
            || command.grant.owner_domain_cookie != identity.domain_cookie
        {
            return Err(HostedIrqArenaError::InvalidCommand);
        }
        self.0.publish(
            control,
            identity,
            transaction,
            HostedIrqLaneDirection::Service,
            depth,
            HostedIrqWireCommand {
                kind: command.kind as u32,
                argument_count: command.argument_count as u32,
                operation: command.service_id,
                target0: command.target_domain_id,
                target1: command.target_domain_cookie,
                context: 0,
                irql: 0,
                grant: command.grant,
                arguments: command.arguments,
            },
        )
    }

    pub fn root_begin(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<HostedIrqServiceCommand, HostedIrqArenaError> {
        let wire = self
            .0
            .begin(control, identity, token, HostedIrqLaneDirection::Service)?;
        let Some(kind) = HostedIrqServiceKind::from_raw(wire.kind) else {
            return Err(HostedIrqArenaError::InvalidCommand);
        };
        let command = HostedIrqServiceCommand {
            kind,
            service_id: wire.operation,
            target_domain_id: wire.target0,
            target_domain_cookie: wire.target1,
            grant: wire.grant,
            argument_count: wire.argument_count as u8,
            arguments: wire.arguments,
        };
        if command.valid() {
            if command.grant.owner_domain_id == identity.domain_id
                && command.grant.owner_domain_cookie == identity.domain_cookie
            {
                Ok(command)
            } else {
                Err(HostedIrqArenaError::InvalidCommand)
            }
        } else {
            Err(HostedIrqArenaError::InvalidCommand)
        }
    }

    pub fn root_complete(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
        result: HostedIrqArenaResult,
    ) -> Result<(), HostedIrqArenaError> {
        self.0.complete(
            control,
            identity,
            token,
            HostedIrqLaneDirection::Service,
            result,
        )
    }

    pub fn worker_completion(
        &self,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<HostedIrqArenaResult, HostedIrqArenaError> {
        self.0
            .completion(identity, token, HostedIrqLaneDirection::Service)
    }

    pub fn worker_acknowledge(
        &self,
        control: &HostedIrqArenaControl,
        identity: HostedIrqLaneIdentity,
        token: HostedIrqArenaToken,
    ) -> Result<(), HostedIrqArenaError> {
        self.0
            .acknowledge(control, identity, token, HostedIrqLaneDirection::Service)
    }
}

/// Aggregate pointer view of the fixed 33-page mapping. It intentionally has no constructor: the
/// executive must map every frame and initialize pages in place rather than materializing 132 KiB
/// on a kernel stack.
#[repr(C, align(4096))]
pub struct HostedIrqArena {
    pub control: HostedIrqArenaControl,
    pub dispatch: [HostedIrqDispatchPage; HOSTED_IRQ_ARENA_DEPTH],
    pub service: [HostedIrqServicePage; HOSTED_IRQ_ARENA_DEPTH],
}

impl HostedIrqArena {
    /// Initialize a fully mapped arena without constructing the 33-page aggregate on the stack.
    ///
    /// # Safety
    ///
    /// `arena` must be page aligned, writable for [`HOSTED_IRQ_ARENA_BYTES`], exclusively owned for
    /// the duration of initialization, and not observable by the worker until this method returns.
    pub unsafe fn initialize_in_place(
        arena: *mut Self,
        config: HostedIrqArenaConfig,
    ) -> Result<(), HostedIrqArenaError> {
        if arena.is_null() || arena as usize & (PAGE_SIZE as usize - 1) != 0 {
            return Err(HostedIrqArenaError::InvalidLayout);
        }
        let control = HostedIrqArenaControl::new(config)?;
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*arena).control), control);
            for depth in 0..HOSTED_IRQ_ARENA_DEPTH {
                core::ptr::write(
                    core::ptr::addr_of_mut!((*arena).dispatch[depth]),
                    HostedIrqDispatchPage::new(config.identity),
                );
                core::ptr::write(
                    core::ptr::addr_of_mut!((*arena).service[depth]),
                    HostedIrqServicePage::new(config.identity),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{align_of, size_of};

    fn identity() -> HostedIrqLaneIdentity {
        HostedIrqLaneIdentity::new(7, 9, 11).unwrap()
    }

    fn grant() -> HostedIrqGrantIdentity {
        HostedIrqGrantIdentity::new(7, 9, 19, 23).unwrap()
    }

    fn config() -> HostedIrqArenaConfig {
        HostedIrqArenaConfig {
            identity: identity(),
            component_kpcr_va: 0x4000,
            stack_low: 0x8000,
            stack_high: 0x28_000,
            high_irql: 15,
        }
    }

    fn dispatch(kind: HostedIrqDispatchKind) -> HostedIrqDispatchCommand {
        let (entry_irql, synchronize_irql) = match kind {
            HostedIrqDispatchKind::InterruptService => (5, 7),
            HostedIrqDispatchKind::DeferredProcedure => (2, 2),
            HostedIrqDispatchKind::ProviderCallback => (2, 2),
        };
        HostedIrqDispatchCommand {
            kind,
            work_id: 29,
            routine: 0x1000,
            object: 0x2000,
            context: 0x3000,
            entry_irql,
            synchronize_irql,
            grant: grant(),
            argument_count: 3,
            arguments: [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn dispatch_kind_selects_one_exact_transaction_class() {
        assert_eq!(
            dispatch(HostedIrqDispatchKind::InterruptService).transaction_class(),
            HostedIrqTransactionClass::Interrupt
        );
        assert_eq!(
            dispatch(HostedIrqDispatchKind::DeferredProcedure).transaction_class(),
            HostedIrqTransactionClass::Dpc
        );
        assert_eq!(
            dispatch(HostedIrqDispatchKind::ProviderCallback).transaction_class(),
            HostedIrqTransactionClass::Callback
        );
        assert_eq!(
            dispatch(HostedIrqDispatchKind::InterruptService).execution_irql(),
            7
        );
        assert_eq!(
            dispatch(HostedIrqDispatchKind::DeferredProcedure).execution_irql(),
            2
        );
        assert_eq!(
            dispatch(HostedIrqDispatchKind::ProviderCallback).execution_irql(),
            2
        );
    }

    #[test]
    fn service_kind_preserves_distinct_broker_operations() {
        assert_eq!(
            HostedIrqServiceKind::from_raw(1),
            Some(HostedIrqServiceKind::ProviderImport)
        );
        assert_eq!(
            HostedIrqServiceKind::from_raw(2),
            Some(HostedIrqServiceKind::ProviderCallbackRequest)
        );
        assert_eq!(
            HostedIrqServiceKind::from_raw(3),
            Some(HostedIrqServiceKind::QueueDpc)
        );
        assert_eq!(
            HostedIrqServiceKind::from_raw(4),
            Some(HostedIrqServiceKind::AcquireActualLock)
        );
        assert_eq!(
            HostedIrqServiceKind::from_raw(5),
            Some(HostedIrqServiceKind::ReleaseActualLock)
        );
        assert_eq!(HostedIrqServiceKind::from_raw(6), None);
        assert!(HostedIrqServiceKind::ProviderCallbackRequest.may_request_nested_dispatch());
        assert!(!HostedIrqServiceKind::ProviderImport.may_request_nested_dispatch());

        let mut acquire = service();
        acquire.kind = HostedIrqServiceKind::AcquireActualLock;
        acquire.argument_count = 0;
        assert!(acquire.valid());
        acquire.argument_count = 1;
        assert!(!acquire.valid());

        let mut release = service();
        release.kind = HostedIrqServiceKind::ReleaseActualLock;
        release.argument_count = 1;
        assert!(release.valid());
        release.arguments[0] = 0;
        assert!(!release.valid());

        let mut queue_dpc = service();
        queue_dpc.kind = HostedIrqServiceKind::QueueDpc;
        queue_dpc.argument_count = 4;
        assert!(queue_dpc.valid());
        queue_dpc.arguments[0] = 0;
        assert!(!queue_dpc.valid());
        queue_dpc.arguments[0] = 43;
        queue_dpc.argument_count = 3;
        assert!(!queue_dpc.valid());
    }

    fn service() -> HostedIrqServiceCommand {
        HostedIrqServiceCommand {
            kind: HostedIrqServiceKind::ProviderImport,
            service_id: 31,
            target_domain_id: 37,
            target_domain_cookie: 41,
            grant: grant(),
            argument_count: 2,
            arguments: [43, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn active_control() -> HostedIrqArenaControl {
        let control = HostedIrqArenaControl::new(config()).unwrap();
        control.worker_mark_ready(identity()).unwrap();
        control.root_activate(identity()).unwrap();
        control
    }

    fn success(value: u64) -> HostedIrqArenaResult {
        HostedIrqArenaResult {
            status: 0,
            faulted: false,
            value_count: 1,
            values: [value, 0, 0, 0],
        }
    }

    #[test]
    fn layout_assigns_one_control_and_two_disjoint_depth_runs() {
        assert_eq!(HOSTED_IRQ_ARENA_PAGE_COUNT, 33);
        assert_eq!(HOSTED_IRQ_ARENA_BYTES, 33 * PAGE_SIZE);
        assert_eq!(HostedIrqArenaLayout::control_page_index(), 0);
        assert_eq!(HostedIrqArenaLayout::dispatch_page_index(0), Some(1));
        assert_eq!(HostedIrqArenaLayout::dispatch_page_index(15), Some(16));
        assert_eq!(HostedIrqArenaLayout::service_page_index(0), Some(17));
        assert_eq!(HostedIrqArenaLayout::service_page_index(15), Some(32));
        assert_eq!(HostedIrqArenaLayout::dispatch_page_index(16), None);
        assert_eq!(HostedIrqArenaLayout::service_page_index(16), None);
        assert_eq!(HostedIrqArenaLayout::page_offset(32), Some(32 * PAGE_SIZE));
        assert_eq!(HostedIrqArenaLayout::page_offset(33), None);
    }

    #[test]
    fn transport_words_roundtrip_exact_token_and_reject_reserved_bits() {
        assert_eq!(identity().ready_transport_words(), [11, 0, 0, 0x100]);
        let token = HostedIrqArenaToken {
            lane_generation: 11,
            transaction: 13,
            sequence: 17,
            depth: 15,
            direction: HostedIrqLaneDirection::Service,
        };
        let words = token.transport_words();
        assert_eq!(words, [11, 13, 17, 0x20f]);
        assert_eq!(
            HostedIrqArenaToken::from_transport_words(words),
            Some(token)
        );
        assert_eq!(
            HostedIrqArenaToken::from_transport_words([11, 13, 17, 0x1_020f]),
            None
        );
        assert_eq!(
            HostedIrqArenaToken::from_transport_words([11, 13, 17, 0x30f]),
            None
        );
        assert_eq!(
            HostedIrqArenaToken::from_transport_words([11, 13, 17, 0x210]),
            None
        );
    }

    #[test]
    fn transport_decoder_accepts_ready_and_nested_same_transaction_tokens() {
        let identity = identity();
        assert_eq!(
            decode_hosted_irq_transport_message(identity, None, identity.ready_transport_words()),
            Some(HostedIrqTransportMessage::Ready)
        );
        let dispatch = HostedIrqArenaToken {
            lane_generation: identity.lane_generation,
            transaction: 13,
            sequence: 17,
            depth: 0,
            direction: HostedIrqLaneDirection::Dispatch,
        };
        let service = HostedIrqArenaToken {
            sequence: 18,
            direction: HostedIrqLaneDirection::Service,
            ..dispatch
        };
        assert_eq!(
            decode_hosted_irq_transport_message(
                identity,
                Some(dispatch),
                service.transport_words()
            ),
            Some(HostedIrqTransportMessage::Token(service))
        );
        let nested_dispatch = HostedIrqArenaToken {
            sequence: 19,
            depth: 1,
            direction: HostedIrqLaneDirection::Dispatch,
            ..service
        };
        assert_eq!(
            decode_hosted_irq_transport_message(
                identity,
                Some(service),
                nested_dispatch.transport_words()
            ),
            Some(HostedIrqTransportMessage::Token(nested_dispatch))
        );
        assert_eq!(
            decode_hosted_irq_transport_message(
                identity,
                Some(nested_dispatch),
                dispatch.transport_words()
            ),
            Some(HostedIrqTransportMessage::Token(dispatch))
        );
    }

    #[test]
    fn transport_decoder_rejects_wrong_phase_lane_transaction_and_shape() {
        let identity = identity();
        let dispatch = HostedIrqArenaToken {
            lane_generation: identity.lane_generation,
            transaction: 13,
            sequence: 17,
            depth: 0,
            direction: HostedIrqLaneDirection::Dispatch,
        };
        assert_eq!(
            decode_hosted_irq_transport_message(identity, None, dispatch.transport_words()),
            None
        );
        assert_eq!(
            decode_hosted_irq_transport_message(
                identity,
                Some(dispatch),
                HostedIrqArenaToken {
                    lane_generation: identity.lane_generation + 1,
                    ..dispatch
                }
                .transport_words()
            ),
            None
        );
        assert_eq!(
            decode_hosted_irq_transport_message(
                identity,
                Some(dispatch),
                HostedIrqArenaToken {
                    transaction: dispatch.transaction + 1,
                    ..dispatch
                }
                .transport_words()
            ),
            None
        );
        assert_eq!(
            decode_hosted_irq_transport_message(
                identity,
                Some(dispatch),
                [identity.lane_generation, dispatch.transaction, 0, 0x100]
            ),
            None
        );
        assert_eq!(
            decode_hosted_irq_transport_message(
                HostedIrqLaneIdentity {
                    lane_generation: 0,
                    ..identity
                },
                None,
                identity.ready_transport_words()
            ),
            None
        );
    }

    #[test]
    fn every_protocol_object_is_cache_aligned_and_page_safe() {
        assert_eq!(align_of::<HostedIrqArenaControl>(), PAGE_SIZE as usize);
        assert_eq!(align_of::<HostedIrqDispatchPage>(), PAGE_SIZE as usize);
        assert_eq!(align_of::<HostedIrqServicePage>(), PAGE_SIZE as usize);
        assert_eq!(align_of::<HostedIrqArena>(), PAGE_SIZE as usize);
        assert_eq!(size_of::<HostedIrqArenaControl>(), PAGE_SIZE as usize);
        assert_eq!(size_of::<HostedIrqDispatchPage>(), PAGE_SIZE as usize);
        assert_eq!(size_of::<HostedIrqServicePage>(), PAGE_SIZE as usize);
        assert_eq!(size_of::<HostedIrqArena>(), HOSTED_IRQ_ARENA_BYTES as usize);
        assert_eq!(core::mem::offset_of!(HostedIrqArena, dispatch), 0x1000);
        assert_eq!(core::mem::offset_of!(HostedIrqArena, service), 0x11_000);
    }

    #[test]
    fn aggregate_initializes_in_place_without_a_stack_sized_arena_value() {
        use std::alloc::{alloc_zeroed, dealloc, Layout};

        let layout =
            Layout::from_size_align(HOSTED_IRQ_ARENA_BYTES as usize, PAGE_SIZE as usize).unwrap();
        // SAFETY: the test allocates the exact size/alignment required by initialize_in_place and
        // keeps the allocation exclusively owned until every page has been inspected.
        unsafe {
            let allocation = alloc_zeroed(layout);
            assert!(!allocation.is_null());
            let arena = allocation.cast::<HostedIrqArena>();
            HostedIrqArena::initialize_in_place(arena, config()).unwrap();
            assert_eq!((*arena).control.identity(), Some(identity()));
            for depth in 0..HOSTED_IRQ_ARENA_DEPTH {
                assert_eq!((*arena).dispatch[depth].0.identity(), Some(identity()));
                assert_eq!((*arena).service[depth].0.identity(), Some(identity()));
            }
            dealloc(allocation, layout);
        }
    }

    #[test]
    fn dispatch_roundtrip_is_transaction_depth_and_sequence_bound() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        assert_eq!(
            control.active_transaction(identity(), transaction.transaction),
            Ok(transaction)
        );
        let command = dispatch(HostedIrqDispatchKind::InterruptService);
        let token = page
            .root_publish(&control, identity(), transaction, 0, command)
            .unwrap();
        assert_eq!(page.worker_begin(&control, identity(), token), Ok(command));
        page.worker_complete(&control, identity(), token, success(1))
            .unwrap();
        assert_eq!(page.root_completion(identity(), token), Ok(success(1)));
        page.root_acknowledge(&control, identity(), token).unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }

    #[test]
    fn synchronous_service_uses_a_different_page_under_its_dispatch() {
        let control = active_control();
        let dispatch_page = HostedIrqDispatchPage::new(identity());
        let service_page = HostedIrqServicePage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let dispatch_token = dispatch_page
            .root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        dispatch_page
            .worker_begin(&control, identity(), dispatch_token)
            .unwrap();
        let service_token = service_page
            .worker_publish(&control, identity(), transaction, 0, service())
            .unwrap();
        assert_eq!(
            service_page.root_begin(&control, identity(), service_token),
            Ok(service())
        );
        service_page
            .root_complete(&control, identity(), service_token, success(0x55))
            .unwrap();
        service_page
            .worker_acknowledge(&control, identity(), service_token)
            .unwrap();
        dispatch_page
            .worker_complete(&control, identity(), dispatch_token, success(1))
            .unwrap();
        dispatch_page
            .root_acknowledge(&control, identity(), dispatch_token)
            .unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }

    #[test]
    fn recursion_requires_parent_service_and_unwinds_lifo() {
        let control = active_control();
        let dispatch0 = HostedIrqDispatchPage::new(identity());
        let dispatch1 = HostedIrqDispatchPage::new(identity());
        let service0 = HostedIrqServicePage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Callback)
            .unwrap();
        let token0 = dispatch0
            .root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::ProviderCallback),
            )
            .unwrap();
        dispatch0
            .worker_begin(&control, identity(), token0)
            .unwrap();
        assert_eq!(
            dispatch1.root_publish(
                &control,
                identity(),
                transaction,
                1,
                dispatch(HostedIrqDispatchKind::ProviderCallback),
            ),
            Err(HostedIrqArenaError::NestingViolation)
        );
        let service_token = service0
            .worker_publish(&control, identity(), transaction, 0, service())
            .unwrap();
        service0
            .root_begin(&control, identity(), service_token)
            .unwrap();
        let token1 = dispatch1
            .root_publish(
                &control,
                identity(),
                transaction,
                1,
                dispatch(HostedIrqDispatchKind::ProviderCallback),
            )
            .unwrap();
        dispatch1
            .worker_begin(&control, identity(), token1)
            .unwrap();
        dispatch1
            .worker_complete(&control, identity(), token1, success(0))
            .unwrap();
        assert_eq!(
            service0.root_complete(&control, identity(), service_token, success(0)),
            Err(HostedIrqArenaError::NestingViolation)
        );
        dispatch1
            .root_acknowledge(&control, identity(), token1)
            .unwrap();
        service0
            .root_complete(&control, identity(), service_token, success(0))
            .unwrap();
        service0
            .worker_acknowledge(&control, identity(), service_token)
            .unwrap();
        dispatch0
            .worker_complete(&control, identity(), token0, success(0))
            .unwrap();
        dispatch0
            .root_acknowledge(&control, identity(), token0)
            .unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }

    #[test]
    fn stale_generation_transaction_depth_and_sequence_fail_closed() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let token = page
            .root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        let mut stale = token;
        stale.sequence += 1;
        assert_eq!(
            page.worker_begin(&control, identity(), stale),
            Err(HostedIrqArenaError::StaleToken)
        );
        stale = token;
        stale.depth = 1;
        assert_eq!(
            page.worker_begin(&control, identity(), stale),
            Err(HostedIrqArenaError::StaleToken)
        );
        let wrong_identity = HostedIrqLaneIdentity::new(7, 9, 12).unwrap();
        assert_eq!(
            page.worker_begin(&control, wrong_identity, token),
            Err(HostedIrqArenaError::InvalidIdentity)
        );
    }

    #[test]
    fn irql_is_lane_local_transaction_bound_and_must_unwind() {
        let control = active_control();
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        control
            .worker_raise_irql(identity(), transaction, 0, 5)
            .unwrap();
        assert_eq!(control.current_irql(identity()), Ok(5));
        assert_eq!(
            control.root_finish_transaction(identity(), transaction),
            Err(HostedIrqArenaError::InvalidIrql)
        );
        assert_eq!(
            control.worker_lower_irql(identity(), transaction, 7, 0),
            Err(HostedIrqArenaError::InvalidIrql)
        );
        control
            .worker_lower_irql(identity(), transaction, 5, 0)
            .unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }

    #[test]
    fn first_fault_is_sticky_and_poison_fences_new_work() {
        let control = active_control();
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let first = HostedIrqFaultRecord {
            kind: HostedIrqFaultKind::WorkerFault,
            transaction: transaction.transaction,
            sequence: 3,
            depth: 0,
            direction: HostedIrqLaneDirection::Dispatch,
            code: 0xc000_0005,
            instruction_pointer: 0x1000,
            address: 0x2000,
            parameters: [1, 2, 3, 4],
        };
        assert_eq!(control.record_first_fault(identity(), first), Ok(true));
        let second = HostedIrqFaultRecord {
            kind: HostedIrqFaultKind::ServiceFault,
            code: 0xdead,
            ..first
        };
        assert_eq!(control.record_first_fault(identity(), second), Ok(false));
        assert_eq!(control.first_fault(identity()), Ok(Some(first)));
        let bugcheck = HostedIrqFaultRecord {
            kind: HostedIrqFaultKind::BugCheck,
            code: 0xdead,
            parameters: [11, 12, 13, 14],
            ..first
        };
        assert_eq!(
            control.record_first_bugcheck(identity(), bugcheck),
            Ok(true)
        );
        assert_eq!(control.first_bugcheck(identity()), Ok(Some(bugcheck)));
        assert_eq!(
            control.record_first_bugcheck(
                identity(),
                HostedIrqFaultRecord {
                    code: 0xbeef,
                    ..bugcheck
                }
            ),
            Ok(false)
        );
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::Poisoned)
        );
    }

    #[test]
    fn shutdown_requires_an_idle_lane_and_is_terminal() {
        let control = active_control();
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        assert_eq!(
            control.root_request_shutdown(identity()),
            Err(HostedIrqArenaError::Busy)
        );
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
        control.root_request_shutdown(identity()).unwrap();
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::Shutdown)
        );
    }

    #[test]
    fn slot_reuse_increments_sequence_and_rejects_the_old_token() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let first_transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let first = page
            .root_publish(
                &control,
                identity(),
                first_transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        page.worker_begin(&control, identity(), first).unwrap();
        page.worker_complete(&control, identity(), first, success(1))
            .unwrap();
        page.root_acknowledge(&control, identity(), first).unwrap();
        control
            .root_finish_transaction(identity(), first_transaction)
            .unwrap();

        let second_transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let second = page
            .root_publish(
                &control,
                identity(),
                second_transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        assert_eq!(second.sequence, first.sequence + 1);
        assert_eq!(
            page.worker_begin(&control, identity(), first),
            Err(HostedIrqArenaError::StaleTransaction)
        );
        page.worker_begin(&control, identity(), second).unwrap();
    }

    #[test]
    fn dpc_requires_a_new_outer_dpc_transaction() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let interrupt = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        assert_eq!(
            page.root_publish(
                &control,
                identity(),
                interrupt,
                0,
                dispatch(HostedIrqDispatchKind::DeferredProcedure),
            ),
            Err(HostedIrqArenaError::InvalidCommand)
        );
        control
            .root_finish_transaction(identity(), interrupt)
            .unwrap();

        let dpc = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Dpc)
            .unwrap();
        let token = page
            .root_publish(
                &control,
                identity(),
                dpc,
                0,
                dispatch(HostedIrqDispatchKind::DeferredProcedure),
            )
            .unwrap();
        page.worker_begin(&control, identity(), token).unwrap();
        page.worker_complete(&control, identity(), token, success(0))
            .unwrap();
        page.root_acknowledge(&control, identity(), token).unwrap();
        control.root_finish_transaction(identity(), dpc).unwrap();
    }

    #[test]
    fn poison_allows_exact_unwind_but_never_new_publication() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let token = page
            .root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        page.worker_begin(&control, identity(), token).unwrap();
        let fault = HostedIrqFaultRecord {
            kind: HostedIrqFaultKind::WorkerFault,
            transaction: transaction.transaction,
            sequence: token.sequence,
            depth: 0,
            direction: HostedIrqLaneDirection::Dispatch,
            code: 0xc000_0005,
            instruction_pointer: 0x1000,
            address: 0x2000,
            parameters: [0; 4],
        };
        control.record_first_fault(identity(), fault).unwrap();
        page.worker_complete(
            &control,
            identity(),
            token,
            HostedIrqArenaResult {
                status: -1,
                faulted: true,
                value_count: 0,
                values: [0; 4],
            },
        )
        .unwrap();
        page.root_acknowledge(&control, identity(), token).unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::Poisoned)
        );
    }

    #[test]
    fn complete_depth_capacity_unwinds_and_depth_sixteen_fails() {
        use std::boxed::Box;
        use std::vec::Vec;

        let control = active_control();
        let dispatch_pages: Vec<Box<HostedIrqDispatchPage>> = (0..HOSTED_IRQ_ARENA_DEPTH)
            .map(|_| Box::new(HostedIrqDispatchPage::new(identity())))
            .collect();
        let service_pages: Vec<Box<HostedIrqServicePage>> = (0..HOSTED_IRQ_ARENA_DEPTH)
            .map(|_| Box::new(HostedIrqServicePage::new(identity())))
            .collect();
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Callback)
            .unwrap();
        let mut dispatch_tokens = [None; HOSTED_IRQ_ARENA_DEPTH];
        let mut service_tokens = [None; HOSTED_IRQ_ARENA_DEPTH];

        for depth in 0..HOSTED_IRQ_ARENA_DEPTH {
            let dispatch_token = dispatch_pages[depth]
                .root_publish(
                    &control,
                    identity(),
                    transaction,
                    depth as u8,
                    dispatch(HostedIrqDispatchKind::ProviderCallback),
                )
                .unwrap();
            dispatch_pages[depth]
                .worker_begin(&control, identity(), dispatch_token)
                .unwrap();
            dispatch_tokens[depth] = Some(dispatch_token);
            if depth + 1 < HOSTED_IRQ_ARENA_DEPTH {
                let service_token = service_pages[depth]
                    .worker_publish(&control, identity(), transaction, depth as u8, service())
                    .unwrap();
                service_pages[depth]
                    .root_begin(&control, identity(), service_token)
                    .unwrap();
                service_tokens[depth] = Some(service_token);
            }
        }

        let service15 = service_pages[15]
            .worker_publish(&control, identity(), transaction, 15, service())
            .unwrap();
        service_pages[15]
            .root_begin(&control, identity(), service15)
            .unwrap();
        let overflow_page = HostedIrqDispatchPage::new(identity());
        assert_eq!(
            overflow_page.root_publish(
                &control,
                identity(),
                transaction,
                16,
                dispatch(HostedIrqDispatchKind::ProviderCallback),
            ),
            Err(HostedIrqArenaError::InvalidDepth)
        );
        service_pages[15]
            .root_complete(&control, identity(), service15, success(0))
            .unwrap();
        service_pages[15]
            .worker_acknowledge(&control, identity(), service15)
            .unwrap();

        for depth in (0..HOSTED_IRQ_ARENA_DEPTH).rev() {
            let dispatch_token = dispatch_tokens[depth].unwrap();
            dispatch_pages[depth]
                .worker_complete(&control, identity(), dispatch_token, success(0))
                .unwrap();
            dispatch_pages[depth]
                .root_acknowledge(&control, identity(), dispatch_token)
                .unwrap();
            if depth != 0 {
                let service_token = service_tokens[depth - 1].unwrap();
                service_pages[depth - 1]
                    .root_complete(&control, identity(), service_token, success(0))
                    .unwrap();
                service_pages[depth - 1]
                    .worker_acknowledge(&control, identity(), service_token)
                    .unwrap();
            }
        }
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
        assert_eq!(
            control.depth_high_water(identity()),
            Ok(HOSTED_IRQ_ARENA_DEPTH as u8)
        );
    }

    #[test]
    fn sequence_exhaustion_is_a_terminal_protocol_fault() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        page.0.sequence.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(
            page.root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            ),
            Err(HostedIrqArenaError::SequenceExhausted)
        );
        assert_eq!(
            control.first_fault(identity()).unwrap().unwrap().kind,
            HostedIrqFaultKind::Protocol
        );
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
        control.root_request_shutdown(identity()).unwrap();
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::Shutdown)
        );
    }

    #[test]
    fn malformed_pending_command_is_poisoned_and_released_without_running() {
        fn verify(tamper: impl FnOnce(&HostedIrqDispatchPage)) {
            let control = active_control();
            let page = HostedIrqDispatchPage::new(identity());
            let transaction = control
                .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
                .unwrap();
            let token = page
                .root_publish(
                    &control,
                    identity(),
                    transaction,
                    0,
                    dispatch(HostedIrqDispatchKind::InterruptService),
                )
                .unwrap();
            tamper(&page);
            assert_eq!(
                page.worker_begin(&control, identity(), token),
                Err(HostedIrqArenaError::InvalidCommand)
            );
            assert_eq!(page.0.state.load(Ordering::Acquire), SLOT_IDLE);
            assert_eq!(control.dispatch_mask.load(Ordering::Acquire), 0);
            assert_eq!(control.dispatch_running_mask.load(Ordering::Acquire), 0);
            control
                .root_finish_transaction(identity(), transaction)
                .unwrap();
            assert_eq!(
                control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
                Err(HostedIrqArenaError::Poisoned)
            );
        }

        verify(|page| {
            page.0.kind.store(
                HostedIrqDispatchKind::DeferredProcedure as u32,
                Ordering::Relaxed,
            );
        });
        verify(|page| page.0.argument_count.store(0x100, Ordering::Relaxed));
        verify(|page| {
            page.0.irql.fetch_or(1 << 24, Ordering::Relaxed);
        });
    }

    #[test]
    fn noncanonical_result_count_is_never_narrowed_into_success() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let token = page
            .root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        page.worker_begin(&control, identity(), token).unwrap();
        page.worker_complete(&control, identity(), token, success(1))
            .unwrap();
        page.0.result_value_count.store(0x100, Ordering::Relaxed);
        assert_eq!(
            page.root_completion(identity(), token),
            Err(HostedIrqArenaError::InvalidResult)
        );
        page.0.result_value_count.store(1, Ordering::Relaxed);
        page.root_acknowledge(&control, identity(), token).unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }

    #[test]
    fn failed_acknowledgement_restores_terminal_state_for_retry() {
        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let token = page
            .root_publish(
                &control,
                identity(),
                transaction,
                0,
                dispatch(HostedIrqDispatchKind::InterruptService),
            )
            .unwrap();
        page.worker_begin(&control, identity(), token).unwrap();
        page.worker_complete(&control, identity(), token, success(1))
            .unwrap();
        control.service_mask.store(1, Ordering::Release);
        assert_eq!(
            page.root_acknowledge(&control, identity(), token),
            Err(HostedIrqArenaError::NestingViolation)
        );
        assert_eq!(page.root_completion(identity(), token), Ok(success(1)));
        control.service_mask.store(0, Ordering::Release);
        page.root_acknowledge(&control, identity(), token).unwrap();
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }

    #[test]
    fn shutdown_is_terminal_for_late_fault_and_bugcheck_reports() {
        let control = active_control();
        control.root_request_shutdown(identity()).unwrap();
        let report = HostedIrqFaultRecord {
            kind: HostedIrqFaultKind::WorkerFault,
            transaction: 0,
            sequence: 0,
            depth: 0,
            direction: HostedIrqLaneDirection::Dispatch,
            code: 1,
            instruction_pointer: 0,
            address: 0,
            parameters: [0; 4],
        };
        assert_eq!(
            control.record_first_fault(identity(), report),
            Err(HostedIrqArenaError::Shutdown)
        );
        assert_eq!(
            control.record_first_bugcheck(
                identity(),
                HostedIrqFaultRecord {
                    kind: HostedIrqFaultKind::BugCheck,
                    ..report
                }
            ),
            Err(HostedIrqArenaError::Shutdown)
        );
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::Shutdown)
        );
    }

    #[test]
    fn transaction_exhaustion_poisons_without_leaving_an_active_sentinel() {
        let control = active_control();
        control
            .transaction_next
            .store(u64::MAX - 1, Ordering::Relaxed);
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::SequenceExhausted)
        );
        assert_eq!(control.active_transaction.load(Ordering::Acquire), 0);
        assert_eq!(
            control.first_fault(identity()).unwrap().unwrap().kind,
            HostedIrqFaultKind::Protocol
        );
        assert_eq!(
            control.root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt),
            Err(HostedIrqArenaError::Poisoned)
        );
    }

    #[test]
    fn invalid_config_grant_and_argument_count_fail_before_state_changes() {
        let invalid = HostedIrqArenaControl::new(HostedIrqArenaConfig {
            identity: identity(),
            component_kpcr_va: 0x4001,
            stack_low: 0x8000,
            stack_high: 0x28_000,
            high_irql: 15,
        });
        assert!(matches!(invalid, Err(HostedIrqArenaError::InvalidLayout)));

        let control = active_control();
        let page = HostedIrqDispatchPage::new(identity());
        let transaction = control
            .root_begin_transaction(identity(), HostedIrqTransactionClass::Interrupt)
            .unwrap();
        let mut command = dispatch(HostedIrqDispatchKind::InterruptService);
        command.grant = HostedIrqGrantIdentity::new(8, 9, 19, 23).unwrap();
        assert_eq!(
            page.root_publish(&control, identity(), transaction, 0, command),
            Err(HostedIrqArenaError::InvalidCommand)
        );
        command = dispatch(HostedIrqDispatchKind::InterruptService);
        command.argument_count = (HOSTED_IRQ_ARENA_ARGUMENT_CAP + 1) as u8;
        assert_eq!(
            page.root_publish(&control, identity(), transaction, 0, command),
            Err(HostedIrqArenaError::InvalidCommand)
        );
        control
            .root_finish_transaction(identity(), transaction)
            .unwrap();
    }
}
