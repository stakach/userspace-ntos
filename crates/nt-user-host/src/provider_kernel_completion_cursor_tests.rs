use super::*;

type CursorLanes = ComponentSuspensionLanes<u64, i32, u64>;

#[test]
fn failed_driver_status_ack_is_progress_with_sibling_work_retained() {
    use nt_component_suspension::{ResumeDemand, ResumeWake};

    let mut f = Fixture::new();
    assert!(!f.activations.has_ready_completion());
    let (_, caller) = f.running(1);
    assert!(!f.activations.has_ready_completion());
    let first = f
        .activations
        .record_completion(caller, &f.pm, &f.catalog, &mut f.lanes, 0xc000_0001)
        .unwrap();
    let second = f.ready(2);
    let mut wake = ResumeWake::new(10, 40).unwrap();
    assert!(f.lanes.next_resumable().is_none());
    let demand = ResumeDemand::observe(f.lanes.execution_busy(), false, || {
        f.activations.has_ready_completion()
    });
    assert_eq!(demand, ResumeDemand::Pending);
    wake.reconcile_demand(demand, 100);
    let mut foreign = bootstrap().into_parts().pm;
    for (now, next) in [(100, 110), (110, 130)] {
        let mut pass = wake.begin_pass(now).unwrap().unwrap();
        let refused = f.activations.acknowledge_completion(first, &mut foreign);
        assert!(refused.is_err());
        wake.finish_pass(
            &mut pass,
            now,
            f.activations.has_ready_completion(),
            refused.is_ok(),
        )
        .unwrap();
        assert_eq!(wake.next_deadline(), Some(next));
        assert_eq!(references(&f.pm, caller.thread()), (2, 2));
    }
    let mut pass = wake.begin_pass(130).unwrap().unwrap();
    let delivered = f
        .activations
        .acknowledge_completion(first, &mut f.pm)
        .map(|status| (status as i32) >= 0);
    assert_eq!(delivered, Ok(false));
    assert_eq!(f.activations.completion(second.caller()), Ok(second));
    wake.finish_pass(
        &mut pass,
        130,
        f.activations.has_ready_completion(),
        delivered.is_ok(),
    )
    .unwrap();
    assert_eq!(wake.next_deadline(), Some(140));
    assert_eq!(references(&f.pm, caller.thread()), (1, 1));
    f.activations
        .acknowledge_completion(second, &mut f.pm)
        .unwrap();
    wake.reconcile(f.activations.has_ready_completion(), 140);
    assert_eq!(wake.next_deadline(), None);
    assert_eq!(references(&f.pm, caller.thread()), (0, 0));
}

struct Fixture {
    pm: ProcessManager,
    native: NativeHandleCaller,
    catalog: ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    lanes: CursorLanes,
    activations: KernelProviderActivations,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = bootstrap().into_parts().pm;
        let native = requestor(&mut pm, 0x3000);
        let mut catalog = ProviderDomainCatalog::new();
        let provider = catalog.register().unwrap();
        Self {
            pm,
            native,
            catalog,
            provider,
            lanes: CursorLanes::new(4, 4),
            activations: KernelProviderActivations::new(),
        }
    }

    fn running(&mut self, id: u64) -> (LaneHandle, KernelProviderCaller) {
        let lane = self.lanes.allocate(binding(id)).unwrap();
        self.lanes
            .begin_dispatch(lane, binding(id).reply_object)
            .unwrap();
        let caller = self
            .activations
            .capture(
                &mut self.pm,
                &self.catalog,
                &self.lanes,
                self.provider,
                lane,
                self.native,
            )
            .unwrap();
        (lane, caller)
    }

    fn complete(&mut self, caller: KernelProviderCaller) -> KernelProviderCompletionReceipt {
        self.activations
            .record_completion(caller, &self.pm, &self.catalog, &mut self.lanes, 0)
            .unwrap()
    }

    fn ready(&mut self, id: u64) -> KernelProviderCompletionReceipt {
        let (_, caller) = self.running(id);
        self.complete(caller)
    }
}

#[test]
fn failed_ack_does_not_repeat_or_starve_sibling_and_next_pass_retries() {
    let mut f = Fixture::new();
    let first = f.ready(1);
    let second = f.ready(2);
    let mut cursor = f.activations.completion_cursor();
    assert_eq!(
        f.activations.next_ready_completion(&mut cursor),
        Some(first)
    );
    let mut foreign = bootstrap().into_parts().pm;
    requestor(&mut foreign, 0x3000);
    assert_eq!(
        f.activations.acknowledge_completion(first, &mut foreign),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&f.pm, first.caller().thread()), (2, 2));
    assert_eq!(
        f.activations.next_ready_completion(&mut cursor),
        Some(second)
    );
    assert_eq!(
        f.activations.acknowledge_completion(second, &mut f.pm),
        Ok(0)
    );
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
    assert_eq!(f.activations.completion(first.caller()), Ok(first));
    let mut retry = f.activations.completion_cursor();
    assert_eq!(f.activations.next_ready_completion(&mut retry), Some(first));
    assert_eq!(
        f.activations.acknowledge_completion(first, &mut f.pm),
        Ok(0)
    );
    assert_eq!(f.activations.next_ready_completion(&mut retry), None);
    assert_eq!(references(&f.pm, first.caller().thread()), (0, 0));
}

#[test]
fn pass_excludes_later_captures_even_after_selected_rows_are_removed() {
    let mut f = Fixture::new();
    let mut empty = f.activations.completion_cursor();
    let first = f.ready(1);
    let second = f.ready(2);
    assert_eq!(f.activations.next_ready_completion(&mut empty), None);
    let mut cursor = f.activations.completion_cursor();
    assert_eq!(
        f.activations.next_ready_completion(&mut cursor),
        Some(first)
    );
    f.activations
        .acknowledge_completion(first, &mut f.pm)
        .unwrap();
    let late = f.ready(3);
    assert_eq!(
        f.activations.next_ready_completion(&mut cursor),
        Some(second)
    );
    f.activations
        .acknowledge_completion(second, &mut f.pm)
        .unwrap();
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
    let mut next = f.activations.completion_cursor();
    assert_eq!(f.activations.next_ready_completion(&mut next), Some(late));
    f.activations
        .acknowledge_completion(late, &mut f.pm)
        .unwrap();
    assert_eq!(f.activations.next_ready_completion(&mut next), None);
}

#[test]
fn unfinished_row_becoming_ready_behind_selection_waits_for_next_pass() {
    let mut f = Fixture::new();
    let (lane, first) = f.running(1);
    f.lanes
        .suspend_running(
            lane,
            first.current_binding(&f.lanes).unwrap().reply_object,
            71,
        )
        .unwrap();
    let second = f.ready(2);
    let mut cursor = f.activations.completion_cursor();
    assert_eq!(
        f.activations.next_ready_completion(&mut cursor),
        Some(second)
    );
    f.lanes
        .resume_external(
            lane,
            first.current_binding(&f.lanes).unwrap().reply_object,
            71,
        )
        .unwrap();
    f.lanes
        .retire_external_running(
            lane,
            first.current_binding(&f.lanes).unwrap().reply_object,
            71,
        )
        .unwrap();
    let first = f.complete(first);
    f.activations
        .acknowledge_completion(second, &mut f.pm)
        .unwrap();
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
    let mut next = f.activations.completion_cursor();
    assert_eq!(f.activations.next_ready_completion(&mut next), Some(first));
    f.activations
        .acknowledge_completion(first, &mut f.pm)
        .unwrap();
    assert_eq!(f.activations.next_ready_completion(&mut next), None);
}

#[test]
fn terminal_pending_is_invisible_until_exact_terminal_retirement() {
    let mut f = Fixture::new();
    let (lane, caller) = f.running(1);
    let reply = caller.current_binding(&f.lanes).unwrap().reply_object;
    let key = SuspensionKey::provider_wait(71);
    f.lanes
        .admit_running(lane, reply, key, 1, caller.owner(), 123)
        .unwrap();
    f.lanes.select(key, 258).unwrap();
    f.lanes.begin_resume(lane, reply, key).unwrap();
    let terminal = f
        .activations
        .retain_terminal_completion(caller, &f.pm, &f.catalog, &mut f.lanes, key, 456, 0)
        .unwrap();
    let mut cursor = f.activations.completion_cursor();
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
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
    let mut failed_retirement = f.activations.completion_cursor();
    assert_eq!(
        f.activations.next_ready_completion(&mut failed_retirement),
        None
    );
    let (receipt, retired) = f
        .activations
        .finish_terminal_completion(caller, &f.pm, &mut f.lanes, terminal, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.payload, 456);
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
    let mut next = f.activations.completion_cursor();
    assert_eq!(
        f.activations.next_ready_completion(&mut next),
        Some(receipt)
    );
    f.activations
        .acknowledge_completion(receipt, &mut f.pm)
        .unwrap();
}

#[test]
fn cursor_selection_does_not_weaken_exact_receipt_authority() {
    let mut f = Fixture::new();
    let original = f.ready(1);
    let mut cursor = f.activations.completion_cursor();
    let selected = f.activations.next_ready_completion(&mut cursor).unwrap();
    assert_eq!(selected, original);
    let forged_status = KernelProviderCompletionReceipt {
        status: 1,
        ..selected
    };
    let mut forged_caller = selected.caller();
    forged_caller.activation += 1;
    let forged_identity = KernelProviderCompletionReceipt {
        caller: forged_caller,
        ..selected
    };
    for forged in [forged_status, forged_identity] {
        assert_eq!(
            f.activations.acknowledge_completion(forged, &mut f.pm),
            Err(STATUS_INVALID_HANDLE)
        );
    }
    let mut foreign = KernelProviderActivations::new();
    assert_eq!(
        foreign.acknowledge_completion(selected, &mut f.pm),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&f.pm, selected.caller().thread()), (1, 1));
    assert_eq!(f.activations.completion(selected.caller()), Ok(selected));
    f.activations
        .acknowledge_completion(selected, &mut f.pm)
        .unwrap();
    assert_eq!(
        f.activations.acknowledge_completion(selected, &mut f.pm),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(f.activations.next_ready_completion(&mut cursor), None);
    assert_eq!(references(&f.pm, selected.caller().thread()), (0, 0));
}
