//! Regression for the boot-2 Winlogon/shared-page collision: process-create never entered
//! win32k, yet NtCreateThread returned INVALID_PARAMETER to the installer helper.

use std::fs;
use std::path::PathBuf;

fn source(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join("../../components/ntos-executive/src").join(name))
        .expect("native source")
}

fn body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).expect("named function");
    let text = &source[start..];
    let open = text.find('{').expect("function body");
    let mut depth = 0;
    for (index, ch) in text.as_bytes()[open..].iter().enumerate() {
        match ch {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 { return &text[..open + index + 1]; }
            }
            _ => {}
        }
    }
    panic!("unterminated function {name}")
}

#[test]
fn shared_page_contention_is_a_no_effect_busy_result() {
    let glue = source("win32k_glue.rs");
    let dispatch = body(&glue, "win32k_dispatch_wide_observed_inner");
    let gate = dispatch.find("if shared_busy").expect("shared publication fence");
    let next = dispatch[gate..]
        .find("if crate::spawn_hosts::shared_ingress")
        .expect("separate post-fence admission") + gate;
    let refusal = &dispatch[gate..next];
    assert!(refusal.contains("STATUS_DEVICE_BUSY"),
        "a pre-entry shared-page refusal must be reported as retriable no-effect busy");
    assert!(!refusal.contains("0xC000_000D") && !refusal.contains("STATUS_INVALID_PARAMETER"),
        "no guest-invalid-argument result is justified before the provider sees the request");
}

#[test]
fn no_effect_process_callout_busy_retains_the_initial_thread_owner() {
    let creation = source("initial_thread_creation.rs");
    let callout = body(&creation, "create_win32_process_before_loader");
    assert!(callout.contains("Win32kProcessCreateResult::NotEntered"),
        "process-create must distinguish a refusal before native entry");
    assert!(callout.to_ascii_lowercase().contains("retry")
        || callout.to_ascii_lowercase().contains("redrive"),
        "busy before entry must have an explicit retry disposition, without replaying an entered effect");
    for route in ["start_configured_initial_thread", "create_foreign_thread"] {
        let path = body(&creation, route);
        assert!(!path.contains("Err(status) if callout_may_retire(self, binding)"),
            "{route} must not cancel every no-effect busy callout as a permanent creation failure");
        assert!(path.contains("STATUS_PENDING"),
            "{route} must not expose the transient pre-entry busy result to kernel32");
        assert!(path.to_ascii_lowercase().contains("retry")
            || path.to_ascii_lowercase().contains("redrive"),
            "{route} needs a retained no-effect retry path for its exact initial-thread owner");
    }
    let lower = creation.to_ascii_lowercase();
    assert!(lower.contains("reply") && (lower.contains("wake") || lower.contains("redrive")),
        "a pending no-effect refusal needs an owned caller Reply and a real wake or redrive");
}

#[test]
fn retained_initial_reply_transfers_exact_active_callback_token() {
    let service = source("service_sec_image.rs");
    let handoff = body(&service, "admit_retained_initial_win32k_dispatch");
    assert!(handoff.matches("pending.snapshot.callback_token").count() >= 2,
        "receive and service waits must use their captured callback token");
    assert!(handoff.contains("retained_initial_callback_transfer"),
        "retained Reply admission must select the active callback transfer");
    assert!(handoff.contains("provider_wait_admit_with_transfer")
        && handoff.contains("lpc_wait_admit_with_transfer"),
        "provider and LPC waits also need the active callback lane token");
    let transfer = body(&service, "retained_initial_callback_transfer");
    assert!(transfer.contains("NestedWaitTransfer::InCallback"),
        "an active callback token cannot be admitted as an ordinary root wait");
}

#[test]
fn retained_initial_owner_must_retire_before_terminal_reply() {
    let creation = source("initial_thread_creation.rs");
    let redrive = body(&creation, "redrive_retry_no_effect");
    assert!(redrive.contains("slot.is_none()") && redrive.contains("RetryPhase::Replying(status)"),
        "terminal status requires proof that the exact creation owner was retired");
    assert!(redrive.contains("RetryPhase::ReplyUncertain"),
        "a retained non-busy effect must keep the source Reply fenced");
}

#[test]
fn retained_initial_reply_fences_all_parked_quiescence_before_redrive() {
    let dispatch = source("executor/syscall_nt.rs");
    let branch = dispatch.split("if lp.msg.m0 == SSN_NT_CREATE_THREAD").nth(1)
        .expect("initial thread syscall branch");
    let transfer = branch.find("take_retry_transferred(caller)").unwrap();
    let park = branch.find("mark_wait_parked(").unwrap();
    let redrive = branch.find("redrive_retry_no_effect(").unwrap();
    assert!(transfer < park && park < redrive,
        "the retained Reply must fence the all-parked check before redrive runs");

    let creation = source("initial_thread_creation.rs");
    let retained = body(&creation, "retained_initial_reply_pending");
    assert!(retained.contains("INITIAL_CREATE_RETRIES")
        && retained.contains("blocks_terminal_quiescence"),
        "the gate must inspect retained Reply ownership, including uncertain rows");
    let service = source("service_sec_image.rs");
    let fence = body(&service, "defer_quiesce_for_root_continuations");
    assert!(fence.contains("retained_initial_reply_pending")
        && fence.contains("defer_quiesce_for_active_user_callbacks"),
        "one root-continuation predicate must cover initial Reply and callback ownership");

    let flow = source("executor/flow.rs");
    for gate in ["park_and_log", "mark_wait_parked"] {
        assert!(body(&flow, gate).contains("defer_quiesce_for_root_continuations"),
            "{gate} must not quiesce while the last parked source has an initial Reply");
    }
    for (file, required) in [
        ("executor/syscall_tail.rs", 3),
        ("executor/vm_fault.rs", 3),
        ("executor/exceptions.rs", 1),
    ] {
        let text = source(file);
        assert!(text.matches("defer_quiesce_for_root_continuations(").count() >= required,
            "{file} has terminal quiesce sites that need the retained Reply fence");
        assert!(!text.contains("defer_quiesce_for_active_user_callbacks("),
            "{file} must not bypass the retained Reply fence at a terminal gate");
    }
    assert!(!flow.contains("defer_quiesce_for_active_user_callbacks("),
        "both common all-live gates must use the root-continuation fence");
}

