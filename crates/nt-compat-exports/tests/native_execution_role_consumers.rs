//! Executive policy that still reads the image catalog's role, instead of the live execution-role
//! chain (`ExecutionRoleLedger`), may only shrink (#310, #429, #432).
//!
//! The ledger includes seeded bootstrap roles and dynamically admitted children. This ratchet
//! keeps remaining catalog-role and parent-walk policy debt visible: a new site fails, and a
//! migrated site must lower its baseline here.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Catalog-role helpers that decide policy from the image catalog, not the live ledger.
const CATALOG_ROLE_CALLS: &[&str] = &[
    "hosted_pi_has_role(",
    "hosted_owner_has_role(",
    "hosted_main_badge_has_role(",
    "current_hosted_process_role(",
    "hosted_pi_for_role(",
    "current_process_is_csrss(",
    "current_process_is_winlogon(",
    "hosted_non_native_top_level_badge(",
    // Installer ownership by catalog image role after a process-manager parent walk.
    ".can_own_installer_service_work(",
];

/// Today's sites, per executive source file (counted call sites, definitions excluded).
const BASELINE: &[(&str, usize)] = &[
    ("exec_file_create.rs", 1),
    ("exec_handler.rs", 21),
    ("executor/admission.rs", 1),
    ("executor/exceptions.rs", 4),
    ("executor/syscall.rs", 1),
    ("executor/syscall_tail.rs", 5),
    ("executor/vm_fault.rs", 3),
    ("service_sec_image.rs", 2),
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
    let source = "fn hosted_pi_has_role(pi: usize) -> bool {\n\
                  // hosted_pi_has_role(x) in a comment\n\
                  if hosted_pi_has_role(pi) && image.can_own_installer_service_work() {}\n\
                  let live = live_hosted_pi_for_role(role);\n";
    assert_eq!(catalog_role_sites(source), 2);
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
fn event_role_checks_require_live_owner_and_preserve_main_badge_scope() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    )
    .expect("executive source");
    let body = |start: &str, end: &str| {
        source.split(start).nth(1).expect("role helper")
            .split(end).next().expect("role helper boundary")
            .chars().filter(|c| !c.is_whitespace()).collect::<String>()
    };
    let pi = body("fn hosted_pi_has_role(", "fn hosted_main_badge_has_role(");
    assert!(pi.contains("live_execution_role(pi)==Some(role)"),
        "catalog role cannot authorize an event for a pending or retired process");

    let main = body("fn hosted_main_badge_has_role(", "fn hosted_owner_has_role(");
    assert!(main.contains("admit_hosted_thread_ingress(badge)"),
        "main badge check must authenticate the event ingress");
    assert!(main.contains("hosted_process_top_badge(runtime.pi)==Some(badge)"),
        "a worker badge must not pass the main badge check");

    let owner = body("fn hosted_owner_has_role(", "fn live_hosted_pi_for_role(");
    assert!(owner.contains("admit_hosted_thread_ingress(badge)"),
        "worker owner check must authenticate the event ingress");
    assert!(owner.contains("hosted_pi_has_role(nt_handler,runtime.pi,role)"),
        "worker role authority must come from its exact admitted owner");
}

#[test]
fn worker_spawn_uses_publication_owner_instead_of_first_catalog_role() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let source = fs::read_to_string(root.join("service_sec_image.rs"))
        .expect("executive source");
    let context = source
        .split("fn live_process_context_for_role(")
        .nth(1)
        .expect("worker context helper")
        .split("unsafe fn spawn_requested_local_thread(")
        .next()
        .expect("worker context boundary");
    let compact: String = context.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("owner_pi:usize") && compact.contains("expected_pid:u64"),
        "worker context must be checked against the already reserved publication owner");
    assert!(compact.contains("live_execution_role(owner_pi)!=Some(role)"),
        "a stale or pending catalog role cannot select a worker owner");
    assert!(!compact.contains("hosted_pi_for_role("),
        "worker owner must not come from the first matching catalog entry");

    let post_loop = fs::read_to_string(root.join("diag/post_loop.rs"))
        .expect("post-loop source");
    assert!(post_loop.contains("unique_live_execution_target("),
        "diagnostic owner selection must refuse ambiguous live roles");
}

#[test]
fn win32k_main_route_uses_admitted_pi_and_live_role() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/executor/syscall.rs"),
    )
    .expect("syscall route source");
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("hosted_process_top_badge(pi)==Some(lp.msg.badge)"),
        "main-badge routing must use the admitted event PI");
    assert!(compact.contains("live_execution_role(pi)"),
        "a catalog role cannot authorize win32k routing for a pending or retired process");
    assert!(!compact.contains("hosted_non_native_top_level_badge("),
        "the old global catalog badge scan must be retired");
    assert!(compact.contains("||is_wl_worker||(is_tp_worker&&pi!=0)"),
        "existing authenticated worker routes must remain available");
}
