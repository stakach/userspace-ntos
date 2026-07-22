//! Host tests for the loader engine — import snap + **forwarders** (the `_vista` proof), the
//! DLL_PROCESS_ATTACH ordering (diamond + cycle), the `PEB->Ldr` list threading, and the
//! `LdrpInitialize` orchestration over a mock module set + a recording [`MockHost`].
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use nt_pe_loader::{ImportRef, ImportedDll};

use super::host::{DllReason, MockHost, NullHost};
use super::init::{self, InitParams, ShimPolicy};
use super::module::{Export, ExportTarget, ForwardSelector, LoadedModule, LoaderState};
use super::{order, peb, resolve};

// --- test helpers ------------------------------------------------------------------------------

/// A concrete export at `base + rva`.
fn addr_export(name: &str, ordinal: u16, base: u64, rva: u64) -> Export {
    Export {
        name: name.to_string(),
        ordinal,
        target: ExportTarget::Address(base + rva),
    }
}

/// A forwarder export `name -> dll.func`.
fn fwd_export(name: &str, ordinal: u16, dll: &str, func: &str) -> Export {
    Export {
        name: name.to_string(),
        ordinal,
        target: ExportTarget::Forwarder {
            dll: dll.to_string(),
            func: ForwardSelector::Name(func.to_string()),
        },
    }
}

/// An import descriptor: DLL + a set of by-name functions (iat slot RVAs auto-assigned).
fn imports(dll: &str, names: &[&str]) -> ImportedDll {
    ImportedDll {
        name: dll.to_string(),
        functions: names
            .iter()
            .enumerate()
            .map(|(i, n)| ImportRef::ByName {
                name: n.to_string(),
                hint: 0,
                iat_slot_rva: 0x2000 + (i as u32) * 8,
            })
            .collect(),
    }
}

// --- (1) import snap + FORWARDERS ---------------------------------------------------------------

#[test]
fn snap_resolves_a_plain_import() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("foo.dll", &["Bar"])],
    ));
    st.add(LoadedModule::mock(
        "foo.dll",
        0x2_0000,
        vec![addr_export("Bar", 1, 0x2_0000, 0x1500)],
        vec![],
    ));

    let resolved = resolve::snap_module(&st, "app.exe").unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].address, 0x2_0000 + 0x1500);
    assert_eq!(resolved[0].from_dll, "foo.dll");
}

/// ★ THE MARQUEE TEST: the `_vista` forwarder pattern resolves WITHOUT any pinning hack.
/// `foo.dll` exports `Bar` as a forwarder to `foo_vista.dll!Bar`; the loader follows it to the
/// concrete address in `foo_vista.dll`. This obsoletes the 3 documented `_vista` pins.
#[test]
fn forwarder_resolves_vista_pattern() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("foo.dll", &["Bar"])],
    ));
    // foo.dll exports Bar as a FORWARDER to foo_vista.dll!Bar (no concrete address).
    st.add(LoadedModule::mock(
        "foo.dll",
        0x2_0000,
        vec![fwd_export("Bar", 1, "foo_vista", "Bar")],
        vec![],
    ));
    // foo_vista.dll has the real Bar.
    st.add(LoadedModule::mock(
        "foo_vista.dll",
        0x3_0000,
        vec![addr_export("Bar", 7, 0x3_0000, 0x900)],
        vec![],
    ));

    let resolved = resolve::snap_module(&st, "app.exe").unwrap();
    assert_eq!(resolved.len(), 1);
    // Resolved to foo_vista.dll's concrete Bar — the forwarder was followed, no pin needed.
    assert_eq!(resolved[0].address, 0x3_0000 + 0x900);
}

/// Forwarder CHAINS resolve: A.Foo -> B.Foo -> C.Foo (concrete).
#[test]
fn forwarder_chain_resolves() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "a.dll",
        0x1_0000,
        vec![fwd_export("Foo", 1, "b", "Foo")],
        vec![],
    ));
    st.add(LoadedModule::mock(
        "b.dll",
        0x2_0000,
        vec![fwd_export("Foo", 1, "c", "Foo")],
        vec![],
    ));
    st.add(LoadedModule::mock(
        "c.dll",
        0x3_0000,
        vec![addr_export("Foo", 1, 0x3_0000, 0x40)],
        vec![],
    ));
    let addr = resolve::resolve_symbol(&st, "a.dll", Some("Foo"), None).unwrap();
    assert_eq!(addr, 0x3_0000 + 0x40);
}

/// A forwarder CYCLE (A.Foo -> B.Foo -> A.Foo) is a structured error, not a spin.
#[test]
fn forwarder_cycle_is_an_error_not_a_spin() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "a.dll",
        0x1_0000,
        vec![fwd_export("Foo", 1, "b", "Foo")],
        vec![],
    ));
    st.add(LoadedModule::mock(
        "b.dll",
        0x2_0000,
        vec![fwd_export("Foo", 1, "a", "Foo")],
        vec![],
    ));
    let err = resolve::resolve_symbol(&st, "a.dll", Some("Foo"), None).unwrap_err();
    assert!(matches!(err, resolve::ResolveError::ForwarderCycle { .. }));
}

/// Forwarder by ORDINAL (`"dll.#3"`) resolves.
#[test]
fn forwarder_by_ordinal_resolves() {
    use super::module::parse_forwarder;
    let t = parse_forwarder("NTDLL.#3");
    match t {
        ExportTarget::Forwarder { dll, func } => {
            assert_eq!(dll, "NTDLL");
            assert_eq!(func, ForwardSelector::Ordinal(3));
        }
        _ => panic!("expected forwarder"),
    }

    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "a.dll",
        0x1_0000,
        vec![fwd_ordinal_export("Foo", 1, "ntdll", 3)],
        vec![],
    ));
    st.add(LoadedModule::mock(
        "ntdll.dll",
        0x2_0000,
        vec![addr_export("RealFoo", 3, 0x2_0000, 0x88)],
        vec![],
    ));
    let addr = resolve::resolve_symbol(&st, "a.dll", Some("Foo"), None).unwrap();
    assert_eq!(addr, 0x2_0000 + 0x88);
}

fn fwd_ordinal_export(name: &str, ordinal: u16, dll: &str, target_ord: u16) -> Export {
    Export {
        name: name.to_string(),
        ordinal,
        target: ExportTarget::Forwarder {
            dll: dll.to_string(),
            func: ForwardSelector::Ordinal(target_ord),
        },
    }
}

#[test]
fn missing_module_is_a_structured_error() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("nope.dll", &["X"])],
    ));
    let err = resolve::snap_module(&st, "app.exe").unwrap_err();
    assert!(matches!(err, resolve::ResolveError::ModuleNotFound(_)));
}

#[test]
fn missing_export_is_a_structured_error() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("foo.dll", &["Absent"])],
    ));
    st.add(LoadedModule::mock(
        "foo.dll",
        0x2_0000,
        vec![addr_export("Present", 1, 0x2_0000, 0x10)],
        vec![],
    ));
    let err = resolve::snap_module(&st, "app.exe").unwrap_err();
    assert!(matches!(err, resolve::ResolveError::ExportNotFound { .. }));
}

#[test]
fn module_names_match_case_insensitively_and_add_dll_suffix() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        // Import descriptor names "NTDLL.dll" (uppercase); module is "ntdll.dll".
        vec![imports("NTDLL.dll", &["NtClose"])],
    ));
    st.add(LoadedModule::mock(
        "ntdll.dll",
        0x2_0000,
        vec![addr_export("NtClose", 1, 0x2_0000, 0x100)],
        vec![],
    ));
    assert!(st.contains("NTDLL"));
    assert!(st.contains("ntdll.dll"));
    let resolved = resolve::snap_module(&st, "app.exe").unwrap();
    assert_eq!(resolved[0].address, 0x2_0000 + 0x100);
}

// --- (2) DLL_PROCESS_ATTACH ordering -----------------------------------------------------------

/// A diamond: app -> {b, c}, both -> d. Init order must place d before b/c, and b/c before app.
#[test]
fn init_order_diamond_dependencies_first() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("b.dll", &[]), imports("c.dll", &[])],
    ));
    st.add(LoadedModule::mock(
        "b.dll",
        0x2_0000,
        vec![],
        vec![imports("d.dll", &[])],
    ));
    st.add(LoadedModule::mock(
        "c.dll",
        0x3_0000,
        vec![],
        vec![imports("d.dll", &[])],
    ));
    st.add(LoadedModule::mock("d.dll", 0x4_0000, vec![], vec![]));

    let names = order::initialization_order_names(&st, &["app.exe"]);
    let pos = |n: &str| names.iter().position(|x| x == n).unwrap();
    assert!(pos("d.dll") < pos("b.dll"));
    assert!(pos("d.dll") < pos("c.dll"));
    assert!(pos("b.dll") < pos("app.exe"));
    assert!(pos("c.dll") < pos("app.exe"));
    assert_eq!(names.len(), 4);
}

/// A cycle: b <-> c. The ordering must terminate (break the back-edge) and include all modules.
#[test]
fn init_order_tolerates_a_cycle() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("b.dll", &[])],
    ));
    st.add(LoadedModule::mock(
        "b.dll",
        0x2_0000,
        vec![],
        vec![imports("c.dll", &[])],
    ));
    st.add(LoadedModule::mock(
        "c.dll",
        0x3_0000,
        vec![],
        vec![imports("b.dll", &[])], // cycle back to b
    ));
    let names = order::initialization_order_names(&st, &["app.exe"]);
    assert_eq!(names.len(), 3);
    // app is a dependent of both → last.
    assert_eq!(names.last().unwrap(), "app.exe");
}

// --- (3) PEB->Ldr construction + list threading ------------------------------------------------

#[test]
fn peb_ldr_lists_thread_and_walk_back() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("b.dll", &[])],
    ));
    st.add(LoadedModule::mock(
        "b.dll",
        0x2_0000,
        vec![],
        vec![imports("ntdll.dll", &[])],
    ));
    st.add(LoadedModule::mock("ntdll.dll", 0x3_0000, vec![], vec![]));

    let load_order: Vec<usize> = (0..st.modules.len()).collect();
    let init_order = order::initialization_order(&st, &["app.exe"]);
    let built = peb::build_ldr(&st, &load_order, &init_order, peb::LdrLayout::default());

    // Walking InLoadOrder recovers the modules in LOAD order.
    let load_walk = peb::walk_in_load_order(&built);
    assert_eq!(load_walk, vec!["app.exe", "b.dll", "ntdll.dll"]);

    // Walking InInitializationOrder recovers them in INIT order (deps first: ntdll, b, app).
    let init_walk = peb::walk_in_init_order(&built);
    let init_names: Vec<String> = init_order
        .iter()
        .map(|&i| st.modules[i].name.clone())
        .collect();
    assert_eq!(init_walk, init_names);
    assert_eq!(init_walk.first().unwrap(), "ntdll.dll");
    assert_eq!(init_walk.last().unwrap(), "app.exe");
}

#[test]
fn circular_links_close_the_list_and_walk_terminates() {
    // The shared primitive both the host model and the on-target PEB->Ldr builder use.
    let head = 0x1000u64;
    let nodes = [0x2000u64, 0x2400, 0x2800];
    let (h, m) = peb::circular_links(head, &nodes);
    // Head → first, head.blink → last.
    assert_eq!(h.flink, 0x2000);
    assert_eq!(h.blink, 0x2800);
    // First: blink=head, flink=second.
    assert_eq!(m[0].blink, head);
    assert_eq!(m[0].flink, 0x2400);
    // Middle.
    assert_eq!(m[1].blink, 0x2000);
    assert_eq!(m[1].flink, 0x2800);
    // Last: flink=head (closes circularly — NEVER a NULL flink, the kernel32 GetModuleFileNameW bug).
    assert_eq!(m[2].blink, 0x2400);
    assert_eq!(m[2].flink, head);

    // Simulate the actual walk `GetModuleFileNameW` does: follow flinks from head, expect to visit
    // all 3 nodes and return to the head (terminate) — with NO NULL flink en route.
    let node_link = |va: u64| {
        nodes
            .iter()
            .position(|&n| n == va)
            .map(|i| m[i])
            .expect("node present")
    };
    let mut cur = h.flink;
    let mut visited = 0usize;
    while cur != head {
        assert_ne!(
            cur, 0,
            "NULL flink during walk — the exact GetModuleFileNameW fault"
        );
        visited += 1;
        cur = node_link(cur).flink;
        assert!(visited <= 3, "walk did not terminate — list not closed");
    }
    assert_eq!(visited, 3);
}

#[test]
fn circular_links_empty_list_points_at_head() {
    // An empty list head points at itself — a valid, walk-terminating (immediately) empty list.
    let (h, m) = peb::circular_links(0x9000, &[]);
    assert_eq!(h.flink, 0x9000);
    assert_eq!(h.blink, 0x9000);
    assert!(m.is_empty());
}

#[test]
fn circular_links_incremental_runtime_add_reappends() {
    // Models the on-target "LdrLoadDll appends a runtime module" case: rethreading the SAME list with
    // one more node keeps the walk complete + terminating (the runtime module appears at the tail).
    let head = 0x1000u64;
    let before = [0x2000u64, 0x2400];
    let (_h0, _m0) = peb::circular_links(head, &before);
    let after = [0x2000u64, 0x2400, 0x2800]; // secur32 appended
    let (h, m) = peb::circular_links(head, &after);
    assert_eq!(h.blink, 0x2800, "runtime module is the new list tail");
    assert_eq!(m[2].flink, head, "new tail closes the list");
    assert_eq!(
        m[1].flink, 0x2800,
        "prior tail now links to the runtime module"
    );
}

#[test]
fn ldr_entry_fields_are_populated() {
    let mut st = LoaderState::new();
    let mut m = LoadedModule::mock("ntdll.dll", 0xABCD_0000, vec![], vec![]);
    m.size_of_image = 0x30_0000;
    m.entry_point_rva = 0x1234;
    st.add(m);
    let built = peb::build_ldr(&st, &[0], &[0], peb::LdrLayout::default());
    let e = &built.entries[0];
    assert_eq!(e.entry.dll_base, 0xABCD_0000);
    assert_eq!(e.entry.size_of_image, 0x30_0000);
    assert_eq!(e.entry.entry_point, 0xABCD_0000 + 0x1234);
    // base_dll_name length in bytes = 2 * "ntdll.dll".len().
    assert_eq!(e.entry.base_dll_name.length as usize, "ntdll.dll".len() * 2);
    assert_eq!(
        e.base_name_utf16,
        "ntdll.dll".encode_utf16().collect::<Vec<u16>>()
    );
}

// --- (4) LdrpInitialize orchestration + LoaderHost seam -----------------------------------------

fn three_module_set() -> LoaderState {
    let mut st = LoaderState::new();
    // app.exe imports one func from b.dll; b.dll imports NtClose from ntdll (a forwarder!).
    let mut app = LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("b.dll", &["BInit"])],
    );
    app.entry_point_rva = 0x500;
    st.add(app);

    let mut b = LoadedModule::mock(
        "b.dll",
        0x2_0000,
        vec![addr_export("BInit", 1, 0x2_0000, 0x700)],
        vec![imports("ntdll.dll", &["NtClose"])],
    );
    b.entry_point_rva = 0x100;
    st.add(b);

    // ntdll exports NtClose as a forwarder to ntdll_vista (proving the loader engine drives it).
    let mut ntdll = LoadedModule::mock(
        "ntdll.dll",
        0x3_0000,
        vec![fwd_export("NtClose", 27, "ntdll_vista", "NtClose")],
        vec![],
    );
    ntdll.entry_point_rva = 0x300;
    st.add(ntdll);

    let mut ntdll_vista = LoadedModule::mock(
        "ntdll_vista.dll",
        0x4_0000,
        vec![addr_export("NtClose", 27, 0x4_0000, 0x2000)],
        vec![],
    );
    ntdll_vista.entry_point_rva = 0x400;
    st.add(ntdll_vista);
    st
}

#[test]
fn ldrp_initialize_drives_the_whole_graph() {
    let mut st = three_module_set();
    let mut host = MockHost::new();
    let params = InitParams {
        root_module: "app.exe".to_string(),
        cookie_seed: 0xDEAD_BEEF_CAFE_0000,
        ..InitParams::default()
    };
    let res = init::ldrp_initialize(&mut st, &params, &mut host).unwrap();

    // Normalized flag set.
    assert_eq!(
        res.normalized_flags & nt_ntdll_layout::RTL_USER_PROC_PARAMS_NORMALIZED,
        1
    );
    // Non-zero cookie.
    assert_ne!(res.process_cookie, 0);

    // Every module was mapped.
    assert_eq!(host.mapped.len(), 4);

    // IAT writes: app imports 1 (BInit → b.dll), b imports 1 (NtClose → resolved through the
    // forwarder to ntdll_vista). Both written.
    let nt_close_write = host
        .iat_writes
        .iter()
        .find(|(base, _, _)| *base == 0x2_0000)
        .expect("b.dll IAT write present");
    assert_eq!(nt_close_write.2, 0x4_0000 + 0x2000); // forwarded to ntdll_vista's NtClose

    // DLL_PROCESS_ATTACH called for the DLLs (not app.exe), in init order (deps first).
    let attach_names: Vec<u64> = host.dll_main_calls.iter().map(|(b, _, _)| *b).collect();
    // ntdll_vista (0x4) and ntdll (0x3) before b (0x2); app (0x1) never gets a DllMain.
    assert!(host
        .dll_main_calls
        .iter()
        .all(|(b, _, r)| *b != 0x1_0000 && *r == DllReason::ProcessAttach));
    let pos = |b: u64| attach_names.iter().position(|x| *x == b);
    assert!(pos(0x2_0000) > pos(0x3_0000)); // b initialized after its import dependency ntdll
                                            // ntdll_vista is a FORWARDER target of ntdll, not an import edge, so it is loaded + initialized
                                            // but not ordered by the import graph — it just must be present (all 3 DLLs get a DllMain).
    assert!(attach_names.contains(&0x4_0000));
    assert_eq!(host.dll_main_calls.len(), 3); // b, ntdll, ntdll_vista (not app.exe)

    // Committed PEB/TEB + transferred to app's entry.
    assert_eq!(host.committed, Some((params.peb_va, params.teb_va)));
    assert_eq!(host.transferred, Some((0x1_0000 + 0x500, params.peb_va)));
    assert_eq!(res.entry_va, 0x1_0000 + 0x500);

    let order = order::initialization_order(&st, &["app.exe"]);
    let call_count = host.dll_main_calls.len();
    assert!(
        init::attach_modules(&mut st, &order, Some("app.exe"), &mut host)
            .unwrap()
            .is_empty()
    );
    assert_eq!(host.dll_main_calls.len(), call_count);
}

/// A DllMain returning FALSE fails the load with STATUS_DLL_INIT_FAILED.
#[test]
fn ldrp_initialize_fails_when_dll_main_returns_false() {
    let mut st = three_module_set();
    let mut host = MockHost::new();
    host.dll_main_fail_base = Some(0x2_0000); // b.dll's DllMain returns FALSE
    let params = InitParams {
        root_module: "app.exe".to_string(),
        ..InitParams::default()
    };
    let err = init::ldrp_initialize(&mut st, &params, &mut host).unwrap_err();
    assert_eq!(err, init::STATUS_DLL_INIT_FAILED);
    assert!(st.modules.iter().all(|module| !module.initialized));
    assert!(host
        .dll_main_calls
        .iter()
        .any(|(base, _, reason)| *base == 0x3_0000 && *reason == DllReason::ProcessDetach));
}

/// A missing dependency aborts LdrpInitialize with STATUS_DLL_NOT_FOUND (not a spin).
#[test]
fn ldrp_initialize_reports_missing_dependency() {
    let mut st = LoaderState::new();
    st.add(LoadedModule::mock(
        "app.exe",
        0x1_0000,
        vec![],
        vec![imports("gone.dll", &["X"])],
    ));
    let mut host = MockHost::new();
    let params = InitParams {
        root_module: "app.exe".to_string(),
        ..InitParams::default()
    };
    let err = init::ldrp_initialize(&mut st, &params, &mut host).unwrap_err();
    assert_eq!(err, init::STATUS_DLL_NOT_FOUND);
}

/// The NullHost never fakes a live op: map_image returns NOT_IMPLEMENTED, so init aborts honestly.
#[test]
fn null_host_never_fakes_a_live_operation() {
    let mut st = three_module_set();
    let mut host = NullHost;
    let params = InitParams {
        root_module: "app.exe".to_string(),
        ..InitParams::default()
    };
    let err = init::ldrp_initialize(&mut st, &params, &mut host).unwrap_err();
    assert_eq!(err, crate::STATUS_NOT_IMPLEMENTED);
}

// --- apphelp / shim policy (the correct behavior, replacing the denylist hack) ------------------

#[test]
fn apphelp_not_loaded_without_a_shim_db() {
    let mut st = three_module_set();
    let mut host = MockHost::new();
    // Default policy = NoShims → apphelp NOT loaded.
    let params = InitParams {
        root_module: "app.exe".to_string(),
        shim_policy: ShimPolicy::NoShims,
        ..InitParams::default()
    };
    let res = init::ldrp_initialize(&mut st, &params, &mut host).unwrap();
    assert!(!res.loaded_apphelp);

    // With a matching shim DB → apphelp IS loaded.
    let mut host2 = MockHost::new();
    let params2 = InitParams {
        root_module: "app.exe".to_string(),
        shim_policy: ShimPolicy::LoadShimEngine,
        ..InitParams::default()
    };
    let res2 = init::ldrp_initialize(&mut st, &params2, &mut host2).unwrap();
    assert!(res2.loaded_apphelp);
}

#[test]
fn process_cookie_is_deterministic_and_nonzero() {
    assert_ne!(init::compute_process_cookie(0), 0); // even a zero seed → non-zero cookie
    assert_eq!(
        init::compute_process_cookie(0x1234_5678_9ABC_DEF0),
        init::compute_process_cookie(0x1234_5678_9ABC_DEF0)
    );
}
