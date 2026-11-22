//! A hosted process-exit callback whose provider pump stops before it returns (#420). The
//! drain keeps it with its ticket, resumes it before claiming any other ticket, and
//! acknowledges it once, on its true return. It never answers an uncertain result for a
//! callback that is still running.

use nt_kernel_exec::hosted_process_exit_notify::{
    CallbackInvocation, ProcessExitDispatchResult, ProcessExitDrain, ProcessExitHost,
    ProcessExitRow, RunningProcessExit,
};

/// A provider call: how many turns it runs before returning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Call { ticket: u32, turns_left: u32 }

#[derive(Default)]
struct Model {
    queue: Vec<(u32, u32)>,
    blocked: bool,
    claimed: Vec<u32>,
    entered: Vec<u32>,
    resumed: Vec<u32>,
    completed: Vec<u32>,
    uncertain_resume: bool,
}

impl Model {
    fn invoke(&mut self, call: Call) -> Result<CallbackInvocation<Call>, u32> {
        if call.turns_left == 0 { Ok(CallbackInvocation::Returned) }
        else { Ok(CallbackInvocation::Running(Call { turns_left: call.turns_left - 1, ..call })) }
    }
}

impl ProcessExitHost<u32, Call> for Model {
    type Error = u32;
    fn may_enter(&mut self) -> bool { !self.blocked }
    fn claim(&mut self) -> Option<u32> {
        if self.queue.is_empty() { return None; }
        let (ticket, _) = self.queue[0];
        self.claimed.push(ticket);
        Some(ticket)
    }
    fn dispatch(&mut self, ticket: &u32) -> ProcessExitDispatchResult<u32, Call> {
        let (_, turns) = self.queue.remove(0);
        self.entered.push(*ticket);
        let call = Call { ticket: *ticket, turns_left: turns };
        let invoked = self.invoke(call);
        match invoked {
            Ok(CallbackInvocation::Returned) => ProcessExitDispatchResult::Completed,
            Ok(CallbackInvocation::Running(call)) => ProcessExitDispatchResult::CallbackRunning(
                RunningProcessExitProbe::running(call).unwrap()),
            Err(error) => ProcessExitDispatchResult::CallbackUncertain(error),
        }
    }
    fn resume(&mut self, ticket: &u32, running: RunningProcessExit<Call>)
        -> ProcessExitDispatchResult<u32, Call> {
        self.resumed.push(*ticket);
        let uncertain = self.uncertain_resume;
        running.resume(|call| if uncertain { Err(0xDEAD) } else { self.invoke(call) }, || Ok(()))
    }
    fn complete(&mut self, ticket: u32) -> Result<(), u32> {
        self.completed.push(ticket);
        Ok(())
    }
}

/// Builds a [`RunningProcessExit`] the only public way: through a running `execute`.
struct RunningProcessExitProbe;
impl RunningProcessExitProbe {
    fn running(call: Call) -> Option<RunningProcessExit<Call>> {
        use nt_kernel_exec::hosted_process_exit_notify::{
            HostedImageIdentity, HostedProcessExitDelivery, HostedProcessNotifyBinding,
            HostedProcessNotifyTransport,
        };
        let binding = HostedProcessNotifyBinding {
            image: HostedImageIdentity { run_base: 0x1000, image_len: 0x1000, publication_generation: 1 },
            transport: HostedProcessNotifyTransport {
                domain_id: 1, domain_cookie: 1, endpoint: 1, vspace: 1, shared: 1,
            },
        };
        let delivery = HostedProcessExitDelivery {
            owner: binding.image.owner_for_callback(0x1010).unwrap(),
            callback: 0x1010, process_id: 4, process_object: 0x9000,
        };
        match binding.plan_exit(delivery, binding)?
            .execute(|_, _| Ok::<_, u32>(CallbackInvocation::Running(call)), || Ok(()))
        {
            ProcessExitDispatchResult::CallbackRunning(running) => Some(running),
            _ => None,
        }
    }
}

#[test]
fn a_running_callback_is_resumed_before_any_other_ticket_is_claimed() {
    let mut row = ProcessExitRow::new();
    let mut host = Model { queue: vec![(1, 2), (2, 0)], ..Model::default() };
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Running);
    assert!(row.is_running());
    // The second turn resumes ticket 1, which is still running: ticket 2 stays unclaimed.
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Running);
    assert_eq!(host.claimed, [1]);
    assert_eq!(host.completed, Vec::<u32>::new());
    // Ticket 1 returns, is acknowledged once, and only then is ticket 2 claimed and run.
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Idle);
    assert_eq!(host.claimed, [1, 2]);
    assert_eq!(host.resumed, [1, 1]);
    assert_eq!(host.completed, [1, 2]);
    assert!(!row.is_running());
}

#[test]
fn a_turn_that_may_not_enter_claims_nothing_and_keeps_the_running_callback() {
    let mut row = ProcessExitRow::new();
    let mut host = Model { queue: vec![(1, 1), (2, 0)], ..Model::default() };
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Running);
    host.blocked = true;
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Running);
    assert_eq!(host.resumed, Vec::<u32>::new());
    assert_eq!(host.claimed, [1]);
    host.blocked = false;
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Idle);
    assert_eq!(host.completed, [1, 2]);
    // A turn that may not enter never claims a fresh ticket either.
    let mut row = ProcessExitRow::<u32, Call>::new();
    let mut host = Model { queue: vec![(3, 0)], blocked: true, ..Model::default() };
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Idle);
    assert_eq!(host.claimed, Vec::<u32>::new());
}

#[test]
fn an_uncertain_resume_retains_its_ticket_unacknowledged() {
    let mut row = ProcessExitRow::new();
    let mut host = Model { queue: vec![(1, 1), (2, 0)], ..Model::default() };
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Running);
    host.uncertain_resume = true;
    assert_eq!(row.drain(&mut host), ProcessExitDrain::Retained(0xDEAD));
    assert_eq!(host.completed, Vec::<u32>::new());
    assert_eq!(host.claimed, [1]);
    assert!(!row.is_running());
}
