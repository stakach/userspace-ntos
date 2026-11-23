//! Executive policy that still reads the image catalog's role, instead of the live execution-role
//! chain (`ExecutionRoleLedger`), may only shrink (#310, #429, #432).
//!
//! The ledger includes seeded bootstrap roles and dynamically admitted children. This ratchet
//! keeps remaining catalog-role and parent-walk policy debt visible: a new site fails, and a
//! migrated site must lower its baseline here.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Direct catalog-role reads still need to be reviewed and migrated case by case.
const CATALOG_ROLE_CALLS: &[&str] = &[
    ".hosted_process_role(",
];

/// Today's sites, per executive source file (counted call sites, definitions excluded).
const BASELINE: &[(&str, usize)] = &[
    ("initial_thread_creation.rs", 1),
];

fn executive_sources(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).expect("executive source directory") {
        let path: PathBuf = entry.expect("source entry").path();
        if path.is_dir() {
            executive_sources(&path, root, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            out.push((relative, fs::read_to_string(&path).expect("source file")));
        }
    }
}

/// Calls of `call` in `line` that are neither a longer identifier ending in it nor its definition.
fn call_sites(line: &str, call: &str) -> usize {
    line.match_indices(call)
        .filter(|(index, _)| {
            let before = &line[..*index];
            let identifier_continues = !call.starts_with('.')
                && before.chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_');
            !identifier_continues && !before.trim_end().ends_with("fn")
        })
        .count()
}

fn catalog_role_sites(source: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| CATALOG_ROLE_CALLS.iter().map(|call| call_sites(line, call)).sum::<usize>())
        .sum()
}

#[test]
fn catalog_role_policy_consumers_never_grow() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../components/ntos-executive/src");
    let mut sources = Vec::new();
    executive_sources(&root, &root, &mut sources);
    let baseline: BTreeMap<&str, usize> = BASELINE.iter().copied().collect();
    let mut grown = Vec::new();
    let mut found = BTreeMap::new();
    for (file, source) in &sources {
        let sites = catalog_role_sites(source);
        if sites == 0 {
            continue;
        }
        found.insert(file.clone(), sites);
        let allowed = baseline.get(file.as_str()).copied().unwrap_or(0);
        if sites > allowed {
            grown.push(format!("{file}: {sites} catalog-role policy sites (baseline {allowed})"));
        }
    }
    assert!(
        grown.is_empty(),
        "new policy must use the live execution-role chain (ExecutionRoleLedger):\n{}",
        grown.join("\n")
    );
    let shrunk: Vec<_> = BASELINE
        .iter()
        .filter(|(file, allowed)| found.get(*file).copied().unwrap_or(0) < *allowed)
        .collect();
    assert!(shrunk.is_empty(), "a site migrated; lower its baseline here: {shrunk:?}");
}

#[test]
fn the_site_counter_ignores_definitions_and_comments() {
    let source = "fn hosted_process_role(pi: usize) -> bool {\n\
                  // handler.hosted_process_role(pi) in a comment\n\
                  let role = handler.hosted_process_role(pi);\n\
                  let live = handler.live_execution_role(pi);\n";
    assert_eq!(catalog_role_sites(source), 1);
}

#[test]
fn dynamic_file_observation_uses_pe_subsystem_after_live_creator_admission() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/exec_handler.rs"),
    )
    .expect("executive source");
    let admission = source
        .split("unsafe fn admit_dynamic_hosted_exe(")
        .nth(1)
        .expect("dynamic File admission")
        .split("unsafe fn dynamic_hosted_identity_attachments_match(")
        .next()
        .expect("admission boundary");
    let compact: String = admission.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains("if!eligible_creator{returnNone;}")
            && compact.find("if!eligible_creator{returnNone;}")
                < compact.find("load_hosted_executable_from_volume_path("),
        "a live eligible creator must be required before loading the dynamic executable"
    );
    assert!(
        compact.contains("HostedProcessRole::for_image_subsystem(pe.subsystem())"),
        "a dynamic File observation must describe the parsed executable, not its creator"
    );
    assert!(
        compact.contains("catalog.admit_dynamic_executable(leaf,role,"),
        "the PE-derived role must reach the catalog admission"
    );
}

#[test]
fn csrss_workers_require_the_committed_live_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/exec_handler.rs"),
    )
    .expect("executive source");
    assert!(source.contains("&& self.current_process_is_csrss()"),
        "the special CSRSS worker path must keep its role gate");
    let gate = source.split("fn current_process_is_csrss(&self) -> bool {").nth(1)
        .expect("CSRSS worker role gate")
        .split("fn current_process_is_lsass(").next().unwrap();
    let compact: String = gate.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains(
        "self.live_execution_role(self.pi)==Some(nt_exe_image::HostedProcessRole::Win32Subsystem)"
    ), "a generic File image must gain CSRSS worker authority only from its committed live role");
}

#[test]
fn current_process_policy_reads_its_committed_live_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/exec_handler.rs"),
    )
    .expect("executive source");
    let helper = source.split("fn current_hosted_process_role(&self) -> Option<nt_exe_image::HostedProcessRole> {")
        .nth(1).expect("current process role helper")
        .split("fn current_process_has_role(").next().unwrap();
    let compact: String = helper.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("self.live_execution_role(self.pi)"),
        "role-owned threads and current-process policy need a committed live role");
    assert!(!compact.contains("current_hosted_process_image"),
        "an observed executable's catalog role is not execution authority");
}

#[test]
fn win32k_dispatch_flags_follow_the_committed_process_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/executor/syscall_win32k.rs"),
    )
    .expect("win32k route source");
    let dispatch = source.split("let process_role = ").nth(1)
        .expect("process role selection")
        .split("let winlogon_gui_client").next().unwrap();
    let compact: String = dispatch.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.starts_with("nt_handler.live_execution_role(pi);"),
        "win32k client flags need the running process's committed role");
    assert!(!source.contains("nt_handler.hosted_process_role(pi)"),
        "later win32k atom and SAS decisions must use the same live role");
}

#[test]
fn active_win32k_callback_client_carries_the_committed_process_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    )
    .expect("win32k client context source");
    let context = source.split("fn win32k_client_context_for_thread(").nth(1)
        .expect("active win32k syscall client")
        .split("unsafe fn sync_win32k_context_to_process_manager(").next().unwrap();
    assert!(context.contains("process_role: nt_handler.live_execution_role(pi)"),
        "the dispatch callback frame must carry the same live role as its syscall route");
}

#[test]
fn provider_retirement_freezes_the_exact_committed_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/exec_handler.rs"),
    )
    .expect("process retirement source");
    let prepare = source.split("pub(crate) fn try_delete_hosted_process_object(").nth(1)
        .expect("hosted process deletion")
        .split("fn trace_hosted_process_delete_blockers(").next().unwrap();
    assert!(prepare.contains("self.execution_roles.role("),
        "the provider finalizer must freeze the generation-bound committed role, not the image catalog");
    assert!(!prepare.contains("self.hosted_process_role(pi)"),
        "a signaled process's catalog role is not retirement authority");
}

#[test]
fn win32k_lifecycle_client_keeps_the_exact_committed_role_after_process_exit() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/main.rs"),
    )
    .expect("win32k lifecycle source");
    let retirement = source.split("unsafe fn release_hosted_thread_win32_context(").nth(1)
        .expect("lifecycle retirement")
        .split("unsafe fn terminate_hosted_thread_mechanism(").next().unwrap();
    assert!(retirement.contains("handler.execution_roles.role("),
        "a signaled process retains an exact committed role until execution retirement");
    assert!(retirement.contains("win32k_lifecycle_client(tid, handler, process_role)"),
        "retirement must pass its exact retained role into the client constructor");
    assert!(!retirement.contains("handler.hosted_process_role(pi)"),
        "provider retirement cannot inherit a replacement catalog role");
}

#[test]
fn initial_win32k_client_does_not_require_a_committed_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/initial_thread_creation.rs"),
    )
    .expect("initial thread source");
    let capture = source.split("unsafe fn capture_initial_win32k_client(").nth(1)
        .expect("pre-commit win32k client capture")
        .split("pub(crate) unsafe fn validate_process_create_provider_caller(").next().unwrap();
    assert!(capture.contains("handler.capture_process_identity(binding.pi) != Some(binding.process)"),
        "the pre-commit observation must be tied to the exact reserved process");
    assert!(capture.contains("win32k_lifecycle_client(binding.tid, handler, role)"),
        "initial process-create must pass its validated pre-commit role explicitly");
    let constructor = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/main.rs"),
    )
    .expect("win32k lifecycle constructor");
    let constructor = constructor.split("fn win32k_lifecycle_client(").nth(1)
        .expect("shared client constructor")
        .split("unsafe fn release_hosted_thread_win32_context(").next().unwrap();
    assert!(!constructor.contains("handler.execution_roles.role("),
        "the shared constructor also serves a pre-commit initial process-create callout");
}

#[test]
fn shell_frontiers_and_completed_paint_use_committed_roles() {
    let service = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    )
    .expect("shell frontier source");
    let body = |start: &str, end: &str| {
        service.split(start).nth(1).expect("frontier function")
            .split(end).next().unwrap()
    };
    for (start, end) in [
        ("unsafe fn progress_stall_deferral_snapshot(", "unsafe fn trace_progress_stall_deferral("),
        ("unsafe fn interactive_shell_chrome_frontier_pending(", "unsafe fn defer_quiesce_for_interactive_shell_chrome("),
        ("unsafe fn pre_user_shell_frontier_pending(", "unsafe fn dump_shell_launch_quiesce("),
        ("fn userinit_shell_frontier_pending(", "fn pi_is_top_level("),
    ] {
        let frontier = body(start, end);
        assert!(frontier.contains("live_hosted_pi_for_execution_role("),
            "{start}: a catalog observation cannot defer or end global quiescence");
        assert!(!frontier.contains("live_hosted_pi_for_observation_role("),
            "{start}: runtime role authority must come from the ledger");
    }
    let selector = body("fn live_hosted_pi_for_execution_role(", "fn hosted_pi_for_top_badge(");
    assert!(selector.contains("unique_live_execution_target(role)"),
        "shell gates must select the unique exact running ledger target");
    let route = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/executor/syscall_win32k.rs"),
    )
    .expect("win32k route source");
    assert!(route.contains("let explorer_direct_gdi_draw = explorer_gui_client"),
        "completed Explorer draws must use the live role already selected for dispatch");
    assert!(!route.contains("observed_explorer_gui_client"),
        "catalog observation cannot advance Explorer's boot milestone counters");
}

#[test]
fn terminal_and_ingress_roles_use_admitted_process_owners() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    )
    .expect("executive service source");
    let body = |start: &str, end: &str| -> String {
        source.split(start).nth(1).expect("role helper")
            .split(end).next().unwrap().chars().filter(|c| !c.is_whitespace()).collect()
    };
    let top = body("fn hosted_pi_for_top_badge(", "fn hosted_non_native_top_level_badge(");
    assert!(top.contains("admit_hosted_thread_ingress(badge)")
        && top.contains("hosted_process_top_badge(runtime.pi)==Some(badge)"),
        "a top-level badge must identify its exact admitted main runtime");
    assert!(!top.contains("0..MAX_PI"), "first-match badge lookup is not authority");

    let direct = body("fn hosted_pi_has_role(", "fn hosted_main_badge_has_role(");
    assert!(direct.contains("live_execution_role(pi)==Some(role)"),
        "terminal decisions need a committed running process role");
    let owner = body("fn hosted_owner_has_role(", "fn hosted_leaf_for_fault_badge(");
    assert!(owner.contains("admit_hosted_thread_ingress(badge)")
        && owner.contains("live_execution_role(runtime.pi)==Some(role)"),
        "worker containment must use the exact admitted owner rather than re-resolving its badge");
    let ingress = body("fn hosted_non_native_top_level_badge(", "fn hosted_pi_has_role(");
    assert!(ingress.contains("live_execution_role(pi)"),
        "win32k ingress must reject a stale or pending process role");
}

#[test]
fn win32k_worker_route_requires_a_live_non_native_owner() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/executor/syscall.rs"),
    )
    .expect("native syscall route source");
    let route = source.split("} else if lp.msg.m0 >= win32k_subsystem::WIN32K_SERVICE_BASE")
        .nth(1).expect("win32k ingress route")
        .split("loop_syscall_win32k::syscall_win32k_route").next().unwrap();
    let compact: String = route.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("(is_wl_worker||is_tp_worker)")
        && compact.contains("live_execution_role(pi)")
        && compact.contains("role!=nt_exe_image::HostedProcessRole::NativeSession"),
        "a worker badge needs a committed, running non-native process role before win32k dispatch");
    assert!(!compact.contains("pi!=0"),
        "a nonzero process slot does not authorize an uncommitted or stale worker");
}

#[test]
fn completed_gui_milestones_require_the_exact_live_caller_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    )
    .expect("native GUI completion source");
    let body = |start: &str, end: &str| -> String {
        source.split(start).nth(1).expect("GUI completion function")
            .split(end).next().unwrap().chars().filter(|c| !c.is_whitespace()).collect()
    };
    let role = body("fn live_gui_caller_role(", "unsafe fn process_completed_user_callback_outer_dispatch(");
    assert!(role.contains("caller.pi()!=pi")
        && role.contains("capture_process_identity(pi)!=Some(caller.process())")
        && role.contains("validate_provider_logical_caller(caller)")
        && role.contains("live_execution_role(pi)"),
        "callback effects need the retained exact caller and committed running role");
    let completion = body("unsafe fn process_completed_user_callback_outer_dispatch(",
        "fn observe_completed_gdi_batch_flush(");
    assert!(completion.contains("live_gui_caller_role(nt_handler,dispatch.logical_caller,completion_pi,")
        && !completion.contains("completion_pi==2"),
        "Winlogon credential and dialog observations cannot depend on a fixed process slot");
    let winlogon = body("unsafe fn observe_winlogon_completed_dispatch(",
        "unsafe fn observe_completed_dialog_modal_dispatch(");
    assert!(winlogon.contains("client_copyin_mapped(pi")
        && !winlogon.contains("client_copyin_mapped(2")
        && !winlogon.contains("csrss_frame_get(2")
        && !winlogon.contains("client_copyin_frame_get(2"),
        "Winlogon's dialog capture must read the proven caller's address space");
    let batch = body("fn observe_completed_gdi_batch_flush(",
        "fn observe_completed_desktop_dispatch(");
    assert!(batch.contains("live_gui_caller_role(nt_handler,Some(caller),caller.pi())")
        && !batch.contains("runtime.observation_role"),
        "a catalog observation cannot credit Explorer's completed GDI batch");
    let mapping = body("fn record_hosted_client_gdi_mapping(", "fn ntgdi_bitmap_format_rgb(");
    assert!(mapping.contains("live_gui_caller_role(nt_handler,caller,pi)")
        && !mapping.contains("image.observation_role()"),
        "a catalog observation cannot credit GUI mapping after the process role is gone");
}

#[test]
fn inline_winlogon_completion_checks_the_exact_live_caller() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/executor/syscall_win32k.rs"),
    )
    .expect("inline win32k route source");
    let completion = source.split("if winlogon_gui_client && lp.msg.m0 == 0x1077")
        .nth(1).expect("inline winlogon completion")
        .split("// ★ BATCH 45").next().unwrap();
    let compact: String = completion.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("live_gui_caller_role(&nt_handler,dispatch_client.logical_caller,pi)")
        && compact.contains("observe_winlogon_completed_dispatch(")
        && compact.contains("piasu64"),
        "inline Winlogon completion must be tied to its retained live caller and process space");
}
