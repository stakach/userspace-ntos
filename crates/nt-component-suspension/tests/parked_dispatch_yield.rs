//! An ordinary dispatch parked in its own wait yields to the root (#420, #427 A).
//!
//! The model is boot 44920424349: condrv waits inside cmd's DEVICE_CONTROL for conhost's
//! answer, and conhost answers only through hosted syscalls of its own. The root may deliver
//! those only from its own loop, never from inside the parked dispatch's pump.

use nt_component_suspension::{
    kept_dispatch_turn, parked_dispatch_receive, settle_unfinished, IngressExecutionOwner,
    KeptDispatchTurn, ParkedDispatch, ParkedDispatchReceive, UnfinishedSettle,
};

const ROOT_FILE_DISPATCH: ParkedDispatch = ParkedDispatch {
    own_wait_parked: true,
    owner_keeps_continuation: true,
    nested_in_lane: false,
    enclosing_receive: false,
};

#[derive(Debug, Default)]
struct Boot {
    /// Root is inside cmd's IRP pump (the provider lane is condrv's primary).
    in_pump: bool,
    /// The File row keeps the pump's receive half.
    kept: bool,
    /// The parked wait's `HOSTED_DRIVER_WAITERS` row (instance + route).
    waiter_row: bool,
    /// conhost's answer has been delivered and acknowledged the parked Call.
    wake_acknowledged: bool,
    /// conhost's hosted syscalls, still undelivered.
    hosted: Vec<&'static str>,
    delivered: Vec<&'static str>,
    /// Receive owners root used once the pump had yielded.
    root_receive_owners: Vec<IngressExecutionOwner>,
    resumes: u32,
    completed: Option<i32>,
}

impl Boot {
    fn new() -> Self {
        Self {
            in_pump: true,
            waiter_row: true,
            hosted: vec!["conhost NtClose", "conhost NtDeviceIoControlFile(answer)"],
            ..Self::default()
        }
    }

    /// One root step, using exactly the policy the executive applies.
    fn step(&mut self) {
        if self.in_pump {
            match parked_dispatch_receive(ROOT_FILE_DISPATCH) {
                // The pump's own receive sees only provider Calls and timers: the wait times
                // out, condrv waits again, and hosted Calls stay retained, undelivered.
                ParkedDispatchReceive::Continue => {}
                ParkedDispatchReceive::YieldToRoot => {
                    assert!(self.waiter_row, "the park keeps its waiter row while it yields");
                    assert_eq!(
                        settle_unfinished(true, false, false, false, true),
                        UnfinishedSettle::Keep,
                        "a root caller that may block must not await a parked wait",
                    );
                    self.in_pump = false;
                    self.kept = true;
                }
            }
            return;
        }
        if self.kept {
            match kept_dispatch_turn(self.wake_acknowledged, !self.wake_acknowledged) {
                KeptDispatchTurn::Resume => {
                    self.resumes += 1;
                    self.kept = false;
                    self.completed = Some(0);
                }
                KeptDispatchTurn::AwaitWake => assert!(self.waiter_row),
                KeptDispatchTurn::Fence => panic!("a live parked dispatch was fenced"),
            }
        }
        // The root loop's own receive, with no dispatch entered.
        self.root_receive_owners.push(IngressExecutionOwner::Idle);
        if let Some(call) = (!self.hosted.is_empty()).then(|| self.hosted.remove(0)) {
            self.delivered.push(call);
            if call.ends_with("(answer)") {
                // conhost's answer signals condrv's event: the wake acknowledges the parked
                // Call and retires its waiter row; condrv's next Call is then retained.
                self.waiter_row = false;
                self.wake_acknowledged = true;
            }
        }
    }
}

#[test]
fn a_parked_ordinary_dispatch_yields_to_the_root_rather_than_blocking_it() {
    let mut boot = Boot::new();
    boot.step();
    assert!(!boot.in_pump, "root is still pumping the parked dispatch");
    assert!(boot.kept, "the File row keeps the dispatch's receive half");
    assert!(boot.completed.is_none(), "yielding is not completion");
    assert!(boot.waiter_row);
}

#[test]
fn an_unrelated_syscall_is_delivered_while_another_drivers_dispatch_is_parked() {
    let mut boot = Boot::new();
    for _ in 0..16 {
        boot.step();
        if boot.completed.is_some() { break; }
    }
    assert_eq!(boot.delivered, ["conhost NtClose", "conhost NtDeviceIoControlFile(answer)"]);
    assert_eq!(boot.completed, Some(0), "cmd's dispatch finishes with its true result");
    assert_eq!(boot.resumes, 1, "the wake resumes exactly that dispatch, once");
}

#[test]
fn the_parked_wait_keeps_its_waiter_row_and_root_receives_as_idle() {
    // #427 (B) admits the next IRP on a worker lane while the primary's waiter row exists,
    // and that IRP reaches the root with no dispatch entered.
    let mut boot = Boot::new();
    boot.step();
    boot.step();
    assert!(boot.waiter_row, "the waiter row lasts the whole park");
    assert!(!boot.root_receive_owners.is_empty());
    assert!(boot.root_receive_owners.iter().all(|owner| *owner == IngressExecutionOwner::Idle));
}

#[test]
fn a_redispatched_wait_is_kept_and_only_an_uncertain_stop_is_fenced() {
    assert_eq!(kept_dispatch_turn(true, false), KeptDispatchTurn::Resume);
    assert_eq!(kept_dispatch_turn(false, true), KeptDispatchTurn::AwaitWake);
    assert_eq!(kept_dispatch_turn(false, false), KeptDispatchTurn::Fence);
}

#[test]
fn a_nested_or_unowned_dispatch_keeps_receiving() {
    let nested = ParkedDispatch { nested_in_lane: true, ..ROOT_FILE_DISPATCH };
    let unowned = ParkedDispatch { owner_keeps_continuation: false, ..ROOT_FILE_DISPATCH };
    let running = ParkedDispatch { own_wait_parked: false, ..ROOT_FILE_DISPATCH };
    let enclosed = ParkedDispatch { enclosing_receive: true, ..ROOT_FILE_DISPATCH };
    for dispatch in [nested, unowned, running, enclosed] {
        assert_eq!(parked_dispatch_receive(dispatch), ParkedDispatchReceive::Continue);
    }
    // Other unfinished pumps keep the existing settlement rule.
    assert_eq!(settle_unfinished(false, false, false, false, true), UnfinishedSettle::Settle);
    assert_eq!(settle_unfinished(false, false, false, true, true), UnfinishedSettle::Keep);
    assert_eq!(settle_unfinished(true, true, false, false, true), UnfinishedSettle::Settle);
}
