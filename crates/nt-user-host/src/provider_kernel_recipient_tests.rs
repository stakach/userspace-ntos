use super::*;
use alloc::{boxed::Box, rc::Rc};
use core::cell::Cell;

#[derive(Debug)]
struct Destination {
    value: Box<u64>,
    stopped: bool,
    drops: Rc<Cell<u32>>,
}

impl Destination {
    fn new(value: u64, drops: &Rc<Cell<u32>>) -> Self {
        Self {
            value: Box::new(value),
            stopped: false,
            drops: Rc::clone(drops),
        }
    }

    fn address(&self) -> *const u64 {
        &*self.value
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

type RecipientLanes = ComponentSuspensionLanes<u64, i32, u64>;

struct Fixture {
    pm: ProcessManager,
    native: NativeHandleCaller,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: RecipientLanes,
    lane: LaneHandle,
    activations: KernelProviderActivations<Destination>,
    drops: Rc<Cell<u32>>,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = bootstrap().into_parts().pm;
        let native = requestor(&mut pm, 0x3000);
        let mut catalog = ProviderDomainCatalog::new();
        let provider = catalog.register().unwrap();
        let mut lanes = RecipientLanes::new(2, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        Self {
            pm,
            native,
            catalog,
            provider,
            lanes,
            lane,
            activations: KernelProviderActivations::new(),
            drops: Rc::new(Cell::new(0)),
        }
    }

    fn capture(
        &mut self,
        destination: Destination,
    ) -> Result<KernelProviderCaller, (u32, Destination)> {
        self.activations.capture_with_recipient(
            &mut self.pm,
            &self.catalog,
            &self.lanes,
            self.provider,
            self.lane,
            self.native,
            destination,
        )
    }

    fn running(&mut self) -> KernelProviderCaller {
        self.lanes
            .begin_dispatch(self.lane, binding(1).reply_object)
            .unwrap();
        self.capture(Destination::new(71, &self.drops)).unwrap()
    }

    fn complete(&mut self, caller: KernelProviderCaller) -> KernelProviderCompletionReceipt {
        self.activations
            .record_completion(
                caller,
                &self.pm,
                &self.catalog,
                &mut self.lanes,
                0x4000_0000,
            )
            .unwrap()
    }
}

#[test]
fn capture_failures_return_the_same_owned_destination_without_dropping_it() {
    let mut f = Fixture::new();
    let destination = Destination::new(71, &f.drops);
    let address = destination.address();
    let (status, destination) = f.capture(destination).unwrap_err();
    assert_eq!(status, STATUS_INVALID_HANDLE);
    assert_eq!(destination.address(), address);
    assert_eq!(f.drops.get(), 0);
    f.lanes
        .begin_dispatch(f.lane, binding(1).reply_object)
        .unwrap();
    let mut foreign = bootstrap().into_parts();
    requestor(&mut foreign.pm, 0x3000);
    let (status, destination) = f
        .activations
        .capture_with_recipient(
            &mut foreign.pm,
            &f.catalog,
            &f.lanes,
            f.provider,
            f.lane,
            f.native,
            destination,
        )
        .unwrap_err();
    assert_eq!(status, STATUS_INVALID_HANDLE);
    assert_eq!(destination.address(), address);
    assert_eq!(f.drops.get(), 0);
    let caller = f.capture(destination).unwrap();
    assert_eq!(f.activations.recipient(caller).unwrap().address(), address);
    let duplicate = Destination::new(72, &f.drops);
    let duplicate_address = duplicate.address();
    let (status, duplicate) = f.capture(duplicate).unwrap_err();
    assert_eq!(status, STATUS_INVALID_PARAMETER);
    assert_eq!(duplicate.address(), duplicate_address);
    assert_eq!(f.activations.recipient(caller).unwrap().address(), address);
    assert_eq!(references(&f.pm, caller.thread()), (1, 1));
    assert_eq!(f.drops.get(), 0);
    drop(duplicate);
    assert_eq!(f.drops.get(), 1);
    f.lanes
        .finish_dispatch(f.lane, binding(1).reply_object)
        .unwrap();
    let destination = f
        .activations
        .release_with_recipient(caller, &mut f.pm)
        .unwrap();
    assert_eq!(destination.address(), address);
    drop(destination);
    assert_eq!(f.drops.get(), 2);
    assert_eq!(references(&f.pm, caller.thread()), (0, 0));
}

#[test]
fn parked_and_stopped_work_retains_mutable_destination_without_fabricating_a_return() {
    let mut f = Fixture::new();
    let caller = f.running();
    let address = f.activations.recipient(caller).unwrap().address();
    f.activations.recipient_mut(caller).unwrap().stopped = true;
    assert!(f.activations.completion(caller).is_err());
    f.lanes
        .suspend_running(f.lane, binding(1).reply_object, 91)
        .unwrap();
    assert!(f
        .activations
        .validate(caller, &f.pm, &f.catalog, &f.lanes)
        .is_err());
    assert!(f.activations.recipient(caller).unwrap().stopped);
    assert_eq!(f.activations.recipient(caller).unwrap().address(), address);
    *f.activations.recipient_mut(caller).unwrap().value = 92;
    assert!(f.activations.completion(caller).is_err());
    assert_eq!(references(&f.pm, caller.thread()), (1, 1));
    assert_eq!(f.drops.get(), 0);
    f.lanes
        .resume_external(f.lane, binding(1).reply_object, 91)
        .unwrap();
    f.lanes
        .complete_external(f.lane, binding(1).reply_object, 91)
        .unwrap();
    let destination = f
        .activations
        .release_with_recipient(caller, &mut f.pm)
        .unwrap();
    assert_eq!(*destination.value, 92);
    assert_eq!(destination.address(), address);
    drop(destination);
    assert_eq!(f.drops.get(), 1);
}

#[test]
fn ready_receipt_failures_preserve_destination_until_exactly_once_acknowledgment() {
    let mut f = Fixture::new();
    let caller = f.running();
    let address = f.activations.recipient(caller).unwrap().address();
    let receipt = f.complete(caller);
    assert!(f.activations.recipient_mut(caller).is_err());
    assert!(f
        .activations
        .release_with_recipient(caller, &mut f.pm)
        .is_err());
    let wrong_status = KernelProviderCompletionReceipt {
        status: receipt.status() + 1,
        ..receipt
    };
    let mut stale_caller = caller;
    stale_caller.activation += 1;
    let wrong_caller = KernelProviderCompletionReceipt {
        caller: stale_caller,
        ..receipt
    };
    for wrong in [wrong_status, wrong_caller] {
        assert!(f
            .activations
            .acknowledge_completion_with_recipient(wrong, &mut f.pm)
            .is_err());
    }
    let mut foreign = bootstrap().into_parts();
    requestor(&mut foreign.pm, 0x3000);
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut foreign.pm)
        .is_err());
    let mut foreign_table = KernelProviderActivations::<Destination>::new();
    assert!(foreign_table
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .is_err());
    assert_eq!(f.activations.completion(caller), Ok(receipt));
    assert_eq!(f.activations.recipient(caller).unwrap().address(), address);
    assert_eq!(references(&f.pm, caller.thread()), (1, 1));
    assert_eq!(f.drops.get(), 0);
    let (status, destination) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert_eq!(status, 0x4000_0000);
    assert_eq!(destination.address(), address);
    assert_eq!(references(&f.pm, caller.thread()), (0, 0));
    assert!(f.activations.recipient(caller).is_err());
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .is_err());
    assert_eq!(f.drops.get(), 0);
    drop(destination);
    assert_eq!(f.drops.get(), 1);
}

#[test]
fn pending_terminal_freezes_destination_until_exact_terminal_retirement_and_ack() {
    let mut f = Fixture::new();
    let caller = f.running();
    let address = f.activations.recipient(caller).unwrap().address();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(71);
    f.lanes
        .admit_running(f.lane, reply, key, 1, caller.owner(), 123)
        .unwrap();
    f.lanes.select(key, 258).unwrap();
    f.lanes.begin_resume(f.lane, reply, key).unwrap();
    let terminal = f
        .activations
        .retain_terminal_completion(caller, &f.pm, &f.catalog, &mut f.lanes, key, 456, 0)
        .unwrap();
    let premature = KernelProviderCompletionReceipt { caller, status: 0 };
    assert!(f.activations.recipient_mut(caller).is_err());
    assert!(f.activations.completion(caller).is_err());
    assert!(f
        .activations
        .acknowledge_completion_with_recipient(premature, &mut f.pm)
        .is_err());
    assert!(f
        .activations
        .release_with_recipient(caller, &mut f.pm)
        .is_err());
    for stage in [TerminalStage::LocalDelivery] {
        let mut attempt = f
            .lanes
            .begin_terminal_stage(terminal, reply, stage)
            .unwrap();
        f.lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
    assert!(f
        .activations
        .finish_terminal_completion(
            caller,
            &f.pm,
            &mut f.lanes,
            terminal,
            Err(STATUS_INVALID_HANDLE),
        )
        .unwrap()
        .is_none());
    assert_eq!(f.activations.recipient(caller).unwrap().address(), address);
    assert!(f.activations.recipient_mut(caller).is_err());
    assert_eq!(references(&f.pm, caller.thread()), (1, 1));
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, 456);
    assert_eq!(retired.suspension.completion, 258);
    assert_eq!(receipt.status(), 0);
    assert!(f.activations.recipient_mut(caller).is_err());
    assert_eq!(f.drops.get(), 0);
    let (_, destination) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert_eq!(destination.address(), address);
    drop(destination);
    assert_eq!(f.drops.get(), 1);
}

#[test]
fn independent_provider_recipients_survive_failed_release_without_cross_delivery() {
    let mut f = Fixture::new();
    let first = f.running();
    let first_address = f.activations.recipient(first).unwrap().address();
    f.lanes
        .finish_dispatch(f.lane, binding(1).reply_object)
        .unwrap();
    let second_provider = f.catalog.register().unwrap();
    let second_lane = f.lanes.allocate(binding(2)).unwrap();
    f.lanes
        .begin_dispatch(second_lane, binding(2).reply_object)
        .unwrap();
    let second = f
        .activations
        .capture_with_recipient(
            &mut f.pm,
            &f.catalog,
            &f.lanes,
            second_provider,
            second_lane,
            f.native,
            Destination::new(72, &f.drops),
        )
        .unwrap();
    let second_address = f.activations.recipient(second).unwrap().address();
    assert_ne!(first_address, second_address);
    let mut foreign = bootstrap().into_parts();
    requestor(&mut foreign.pm, 0x3000);
    assert!(f
        .activations
        .release_with_recipient(first, &mut foreign.pm)
        .is_err());
    assert_eq!(
        f.activations.recipient(first).unwrap().address(),
        first_address
    );
    assert_eq!(
        f.activations.recipient(second).unwrap().address(),
        second_address
    );
    assert_eq!(references(&f.pm, first.thread()), (2, 2));
    assert_eq!(f.drops.get(), 0);
    let first_destination = f
        .activations
        .release_with_recipient(first, &mut f.pm)
        .unwrap();
    assert_eq!(first_destination.address(), first_address);
    assert_eq!(
        f.activations.recipient(second).unwrap().address(),
        second_address
    );
    assert_eq!(references(&f.pm, second.thread()), (1, 1));
    let receipt = f.complete(second);
    let (_, second_destination) = f
        .activations
        .acknowledge_completion_with_recipient(receipt, &mut f.pm)
        .unwrap();
    assert_eq!(second_destination.address(), second_address);
    assert_eq!(*second_destination.value, 72);
    assert_eq!(references(&f.pm, second.thread()), (0, 0));
    drop(first_destination);
    drop(second_destination);
    assert_eq!(f.drops.get(), 2);
}
