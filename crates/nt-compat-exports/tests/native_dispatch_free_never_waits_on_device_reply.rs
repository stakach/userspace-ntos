//! ExFreePool runs at DISPATCH_LEVEL on a hosted driver's IRQ lane (a DPC completing an SRB).
//! The component's device-reply lock is held by a PASSIVE lane across a root Call (for example
//! IoGetDeviceProperty). Root cannot answer that Call while it is driving the DPC, and every
//! hosted thread shares root's processor below root's priority, so a DPC that waits for that
//! lock yields forever (boot 44963863150: storahci's DPC spun in `s_ex_free_pool` while its
//! primary lane was inside IoGetDeviceProperty for the second AHCI controller).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use syn::visit::Visit;

/// A called path: its module qualifier, if it names one, and the function.
type Callee = (Option<String>, String);

#[derive(Default)]
struct Calls(BTreeSet<Callee>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let segments: Vec<_> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if let Some(name) = segments.last() {
                let module = segments.len().checked_sub(2).map(|index| segments[index].clone())
                    .filter(|module| !matches!(module.as_str(), "super" | "crate" | "self"));
                self.0.insert((module, name.clone()));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Free functions of the executive by name, with the file that defines each body.
#[derive(Default)]
struct Functions(BTreeMap<String, Vec<(String, BTreeSet<Callee>)>>);

impl Functions {
    /// The bodies a call from `caller_file` can reach: the named module's, else the caller's own
    /// file's, else every definition of the name.
    fn resolve(&self, caller_file: &str, (module, name): &Callee)
        -> Vec<&(String, BTreeSet<Callee>)> {
        let all: Vec<_> = self.0.get(name).into_iter().flatten().collect();
        let in_file = |file: &str| all.iter().copied().filter(|(f, _)| f == file).collect::<Vec<_>>();
        if let Some(module) = module {
            let found = in_file(&format!("{module}.rs"));
            if !found.is_empty() { return found; }
        }
        let local = in_file(caller_file);
        if !local.is_empty() { return local; }
        all
    }
}

struct Collector<'a> {
    file: &'a str,
    functions: &'a mut Functions,
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        self.functions.0.entry(function.sig.ident.to_string()).or_default()
            .push((self.file.to_owned(), calls.0));
        syn::visit::visit_item_fn(self, function);
    }
}

fn executive_functions() -> Functions {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let mut functions = Functions::default();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let file = syn::parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap();
        Collector { file: &name, functions: &mut functions }.visit_file(&file);
    }
    functions
}

/// The call chain from `start` to `target` through executive free functions, if any. Each step
/// is `file:function`.
fn chain(functions: &Functions, start_file: &str, start: &str, target: &str)
    -> Option<Vec<String>> {
    let starts: Vec<_> = functions.0.get(start).into_iter().flatten()
        .filter(|(file, _)| file == start_file).collect();
    assert!(!starts.is_empty(), "{start_file}:{start} exists");
    let mut parent: BTreeMap<String, String> = BTreeMap::new();
    let mut queue: VecDeque<_> = starts.iter()
        .map(|(file, calls)| (format!("{file}:{start}"), file.clone(), calls)).collect();
    let mut seen: BTreeSet<_> = queue.iter().map(|(key, _, _)| key.clone()).collect();
    while let Some((key, file, calls)) = queue.pop_front() {
        for callee in calls {
            // A bugcheck halts the lane; it never returns into the free path.
            if callee.1 == "report" {
                continue;
            }
            for (callee_file, callee_calls) in functions.resolve(&file, callee) {
                let callee_key = format!("{callee_file}:{}", callee.1);
                if !seen.insert(callee_key.clone()) {
                    continue;
                }
                parent.insert(callee_key.clone(), key.clone());
                if callee.1 == target {
                    let mut path = vec![callee_key];
                    while let Some(previous) = parent.get(path.last().unwrap()) {
                        path.push(previous.clone());
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back((callee_key, callee_file.clone(), callee_calls));
            }
        }
    }
    None
}

#[test]
fn a_dispatch_level_pool_free_never_waits_on_the_device_reply_lock() {
    let functions = executive_functions();
    assert!(functions.0.contains_key("component_device_reply_lock"),
        "the device-reply lock this test guards against still exists");
    for free in ["s_ex_free_pool", "s_ex_free_pool_tag"] {
        // The hosted kernel-driver export (win32k's provider pool has its own export).
        assert_eq!(chain(&functions, "driver_launch.rs", free, "component_device_reply_lock"), None,
            "{free} can run on a DPC while a PASSIVE lane holds the device-reply lock across a \
             root Call that root cannot answer until the DPC returns");
    }
}

#[test]
fn a_dpc_is_admitted_only_when_no_lane_holds_the_device_reply_lock() {
    // nt-hosted-runtime device_reply_lock proves the admission and release-wake policy; this pins
    // that the native DPC dispatch and the component guard use it.
    let functions = executive_functions();
    let calls = |file: &str, name: &str| functions.0.get(name).into_iter().flatten()
        .filter(|(f, _)| f == file)
        .flat_map(|(_, calls)| calls.iter().map(|(_, callee)| callee.clone()))
        .collect::<Vec<_>>();
    assert!(calls("hosted_irq_broker.rs", "dispatch_next_dpc").iter()
        .any(|call| call == "hosted_device_reply_dpc_may_start"),
        "no DPC starts over a device-reply holder");
    assert!(calls("hosted_device_reply_lock.rs", "dpc_may_start").iter()
        .any(|call| call == "admit_dpc_over_device_reply_lock"));
    assert!(calls("hosted_device_reply_lock.rs", "component_device_reply_lock").iter()
        .any(|call| call == "try_acquire_device_reply_lock"));
}
