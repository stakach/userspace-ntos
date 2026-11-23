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
    ("exec_handler.rs", 1),
    ("executor/syscall.rs", 2),
    ("hosted_gui_client_info.rs", 1),
    ("initial_thread_creation.rs", 1),
    ("main.rs", 1),
    ("service_sec_image.rs", 3),
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
    let owner = body("fn hosted_owner_has_role(", "fn live_hosted_pi_for_role(");
    assert!(owner.contains("admit_hosted_thread_ingress(badge)")
        && owner.contains("live_execution_role(runtime.pi)==Some(role)"),
        "worker containment must use the exact admitted owner rather than re-resolving its badge");
    let ingress = body("fn hosted_non_native_top_level_badge(", "fn hosted_pi_has_role(");
    assert!(ingress.contains("live_execution_role(pi)"),
        "win32k ingress must reject a stale or pending process role");
}
