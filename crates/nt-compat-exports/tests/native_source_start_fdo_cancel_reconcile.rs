//! Cancellation still reconciles dispatch and completion returns before releasing START owners.

#[test]
fn cancelled_start_fdo_reconciles_both_uncertain_returns_before_retirement() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_start_fdo_work.rs");
    let advance = work.split("unsafe fn advance(&mut self) -> bool {").nth(1).unwrap();
    let advance = advance.split("\n    }\n}").next().unwrap();
    let dispatch_finish = advance.find("if let Some(returned) = self.returned.take() {").unwrap();
    let completion_finish = advance.find("if let Some(returned) = self.ack_return.take() {").unwrap();
    let cancellation = advance.find("return self.advance_cancelled();").unwrap();
    assert!(dispatch_finish < cancellation);
    assert!(completion_finish < cancellation);
    assert!(advance.contains("Err(rejection) => self.returned = Some(rejection.into_return())"));
    assert!(advance.contains("Err((_, returned)) => self.ack_return = Some(returned)"));

    let cancelled = work.split("unsafe fn advance_cancelled(&mut self) -> bool {").nth(1).unwrap();
    let cancelled = cancelled.split("\n    }\n\n    unsafe fn advance_ack").next().unwrap();
    assert!(cancelled.contains("if self.returned.is_some() || self.ack_return.is_some() {"));
    assert!(cancelled.contains("self.poll_provider();"));
    assert!(cancelled.contains("terminal.retire_after_source_stop(io_manager_mut(), witness)"));
}
