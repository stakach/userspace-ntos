//! Executive policy that still reads the image catalog's role, instead of the live execution-role
//! chain (`ExecutionRoleLedger`), may only shrink (#310, #429, #432).
//!
//! The ledger holds smss and dynamically admitted children, but not the static bootstrap slots
//! (csrss, winlogon), so these consumers cannot move until those slots are seeded into it. Until
//! then this ratchet keeps the debt visible: a new catalog-role or parent-walk policy site fails,
//! and a migrated site must lower its baseline here.

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
    "dynamic_child_role(",
    // Installer ownership by catalog image role after a process-manager parent walk.
    ".can_own_installer_service_work(",
];

/// Today's sites, per executive source file (counted call sites, definitions excluded).
const BASELINE: &[(&str, usize)] = &[
    ("diag/post_loop.rs", 1),
    ("exec_file_create.rs", 1),
    ("exec_handler.rs", 23),
    ("executor/admission.rs", 1),
    ("executor/exceptions.rs", 4),
    ("executor/syscall.rs", 2),
    ("executor/syscall_tail.rs", 5),
    ("executor/vm_fault.rs", 3),
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
    let source = "fn hosted_pi_has_role(pi: usize) -> bool {\n\
                  // hosted_pi_has_role(x) in a comment\n\
                  if hosted_pi_has_role(pi) && image.can_own_installer_service_work() {}\n\
                  let live = live_hosted_pi_for_role(role);\n";
    assert_eq!(catalog_role_sites(source), 2);
}
