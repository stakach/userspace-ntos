//! A call graph of the executive's free functions, for tests that pin which native paths a
//! function can reach.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use syn::visit::Visit;

/// A called path: its module qualifier, if it names one, and the function.
pub type Callee = (Option<String>, String);

#[derive(Default)]
pub struct Calls(BTreeSet<Callee>);

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

/// Free functions of the executive by name, with the file that defines each body; and each
/// module a `#[path]` attribute names differently from its file.
#[derive(Default)]
pub struct Functions(
    pub BTreeMap<String, Vec<(String, BTreeSet<Callee>)>>,
    pub BTreeMap<String, String>,
);

impl Functions {
    /// The bodies a call from `caller_file` can reach: the named module's, else the caller's own
    /// file's, else every definition of the name.
    pub fn resolve(&self, caller_file: &str, (module, name): &Callee)
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

    /// [`Functions::resolve`] without the by-name fallback.
    pub fn resolve_exact(&self, caller_file: &str, (module, name): &Callee)
        -> Vec<&(String, BTreeSet<Callee>)> {
        let all: Vec<_> = self.0.get(name).into_iter().flatten().collect();
        let file = module.as_ref().map_or_else(|| caller_file.to_owned(), |module|
            self.1.get(module).cloned().unwrap_or_else(|| format!("{module}.rs")));
        all.into_iter().filter(|(f, _)| *f == file).collect()
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

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        for attribute in &module.attrs {
            let syn::Meta::NameValue(path) = &attribute.meta else { continue };
            if !path.path.is_ident("path") { continue; }
            if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(file), .. }) = &path.value {
                self.functions.1.insert(module.ident.to_string(), file.value());
            }
        }
        syn::visit::visit_item_mod(self, module);
    }
}

pub fn executive_functions() -> Functions {
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
pub fn chain(functions: &Functions, start_file: &str, start: &str, target: &str)
    -> Option<Vec<String>> {
    walk(functions, start_file, start, target, &[], Functions::resolve)
}

/// [`chain`] over exactly resolved calls (the named module's body, else the caller's own
/// file's), entering no function named in `opaque`: a call to one is a leaf. A by-name fallback
/// and a pump's native servicing each reach nearly every executive body.
pub fn exact_chain(functions: &Functions, start_file: &str, start: &str, target: &str,
    opaque: &[&str]) -> Option<Vec<String>> {
    walk(functions, start_file, start, target, opaque, Functions::resolve_exact)
}

fn walk<'f>(functions: &'f Functions, start_file: &str, start: &str, target: &str,
    opaque: &[&str],
    resolve: impl Fn(&'f Functions, &str, &Callee) -> Vec<&'f (String, BTreeSet<Callee>)>,
) -> Option<Vec<String>> {
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
            for (callee_file, callee_calls) in resolve(functions, &file, callee) {
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
                if !opaque.contains(&callee.1.as_str()) {
                    queue.push_back((callee_key, callee_file.clone(), callee_calls));
                }
            }
        }
    }
    None
}
