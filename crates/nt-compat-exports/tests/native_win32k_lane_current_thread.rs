//! Win32k's physical dispatch lanes must not share their current-thread projection.
//! A suspended CSRSS call may hold a native FAST_MUTEX while another lane enters System work.

fn source(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src")
            .join(name),
    )
    .unwrap()
}

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("missing {name}"));
    let body = &source[start..];
    let open = body.find('{').unwrap();
    let mut depth = 0;
    for (index, ch) in body.char_indices().skip(open) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[..=index];
                }
            }
            _ => {}
        }
    }
    panic!("unclosed {name}")
}

#[test]
fn native_physical_worker_wires_the_lane_kpcr_contract() {
    let glue = source("win32k_glue.rs");
    let worker = function(&glue, "initialize_win32k_physical_lane");
    assert!(worker.contains("WIN32K_PHYSICAL_KPCR_LAYOUT.address(worker_index + 1)"));
    assert!(!worker.contains("gs_base: Some(win32k_subsystem::WIN32K_KPCR_VA)"));
    let subsystem = source("win32k_subsystem.rs");
    let current = function(&subsystem, "current_ethread");
    let system = function(&subsystem, "select_initial_system_context");
    assert!(current.contains("current_kpcr_va()"));
    assert!(system.contains("current_kpcr_va()"));
    assert!(!current.contains("WIN32K_KPCR_VA + 0x188"));
    assert!(!system.contains("WIN32K_KPCR_VA + 0x188"));
}

#[test]
fn process_and_thread_callout_slots_are_physical_lane_local() {
    let subsystem = source("win32k_subsystem.rs");
    assert!(!subsystem.contains("const SLOT_W32PROCESS:"));
    assert!(!subsystem.contains("const SLOT_W32THREAD:"));
    let process = function(&subsystem, "ensure_win32k_process_attached");
    let thread = function(&subsystem, "ensure_win32k_threadinfo");
    assert!(process.contains("current_w32process_slot()"));
    assert!(thread.contains("current_w32thread_slot()"));
}

#[test]
fn executive_wall_diagnostic_does_not_read_its_own_gs_as_win32k_context() {
    let glue = source("win32k_glue.rs");
    let backtrace = function(&glue, "win32k_dispatch_backtrace");
    assert!(!backtrace.contains("trace_win32k_wall_context()"));
}

#[test]
fn executive_lpc_service_uses_the_marshaled_client_id() {
    let subsystem = source("win32k_subsystem.rs");
    let service = function(&subsystem, "service_lpc_request");
    assert!(!service.contains("current_lane_ids()"));
    assert!(service.contains("PORT_MESSAGE_CLIENT_PROCESS_OFFSET"));
    assert!(service.contains("PORT_MESSAGE_CLIENT_THREAD_OFFSET"));
}

#[test]
fn callback_resumes_restore_context_on_the_component_lane() {
    let glue = source("win32k_glue.rs");
    assert!(!glue.contains("win32k_subsystem::restore_current_context_for_user_callback_resume("));
    let subsystem = source("win32k_subsystem.rs");
    for boundary in [
        "s_ke_user_mode_callback_rendezvous",
        "provider_wait_rendezvous",
        "lpc_request_wait_reply_retained",
    ] {
        let body = function(&subsystem, boundary);
        assert!(body.contains("restore"), "{boundary} must restore its retained lane before native return");
    }
}

#[test]
fn executive_deadman_avoids_component_gs_context() {
    let main = source("main.rs");
    let watchdog = function(&main, "watchdog_report");
    assert!(!watchdog.contains("trace_win32k_request_context()"));
}

#[test]
fn kernel_wait_resume_reselects_system_after_owner_validation() {
    let context = source("win32k_provider_wait_context.rs");
    let restore = function(&context, "restore");
    let owner_validation = restore
        .find("current_provider_wait_owner() == Some(owner)")
        .unwrap();
    let select_system = restore
        .find("select_initial_system_context()")
        .expect("kernel wait must restore the physical lane's System projection");
    assert!(owner_validation < select_system);
}
