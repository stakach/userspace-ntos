use super::win32k_dispatch_outcome::{Win32kDispatchOutcome, Win32kProcessCreateResult};

#[test]
fn process_create_outcome_keeps_entry_suspension_and_real_return_distinct() {
    let status = 0xC000_000Du64;
    let failed = Win32kDispatchOutcome::Known { value: status, completed: false };
    let returned = Win32kDispatchOutcome::Known { value: 0, completed: true };
    assert_eq!(failed.process_create(false, false),
        Win32kProcessCreateResult::NotEntered(status as u32));
    assert_eq!(failed.process_create(true, false),
        Win32kProcessCreateResult::Indeterminate(status as u32));
    assert_eq!(failed.process_create(true, true), Win32kProcessCreateResult::Suspended);
    assert_eq!(returned.process_create(true, false), Win32kProcessCreateResult::Returned(0));
}
