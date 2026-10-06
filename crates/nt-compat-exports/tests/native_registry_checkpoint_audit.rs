//! Checkpoint receipts observe the actual journal attempt; they never authorize persistence.
use syn::{visit::Visit, Expr, Item, Pat, Stmt};

fn source(name: &str) -> Option<syn::File> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    std::fs::read_to_string(path).ok().map(|text| syn::parse_file(&text).unwrap())
}

fn method(file: &syn::File, name: &str) -> syn::Block {
    file.items.iter().filter_map(|item| match item {
        Item::Impl(item) => Some(item),
        _ => None,
    }).flat_map(|item| &item.items).find_map(|item| match item {
        syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function.block.clone()),
        _ => None,
    }).expect("actual journal method")
}

#[derive(Default)]
struct Effects {
    calls: Vec<String>,
    paths: Vec<String>,
    fields: Vec<String>,
}

impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths.extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member { self.fields.push(name.to_string()); }
        syn::visit::visit_expr_field(self, field);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.calls.push(mac.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_macro(self, mac);
    }
}

fn effects(statement: &Stmt) -> Effects {
    let mut effects = Effects::default();
    effects.visit_stmt(statement);
    effects
}

fn local_name(statement: &Stmt) -> Option<String> {
    let Stmt::Local(local) = statement else { return None; };
    let Pat::Ident(binding) = &local.pat else { return None; };
    Some(binding.ident.to_string())
}

fn has(effects: &Effects, call: &str) -> bool {
    effects.calls.iter().any(|name| name == call)
}

fn latest_global(effects: &Effects) -> bool {
    effects.paths.iter().any(|name| name.starts_with("WRITABLE_FS_SNAPSHOT_"))
}

fn attempt_contract(block: &syn::Block) -> bool {
    let observed: Vec<_> = block.stmts.iter().map(effects).collect();
    let positions = |call: &str| observed.iter().enumerate()
        .filter_map(|(index, item)| has(item, call).then_some(index)).collect::<Vec<_>>();
    let storage_calls = positions("make_durable");
    let hooks = positions("system_journal");
    let finishes = positions("finish");
    let phases = positions("phase");
    let proofs = positions("durability");
    if storage_calls.len() != 1 || hooks.len() != 1 || finishes.len() != 1
        || phases.len() != 2 || proofs.len() != 1 { return false; }
    let (call, hook, finish, proof) = (storage_calls[0], hooks[0], finishes[0], proofs[0]);
    let starts: Vec<_> = observed.iter().enumerate().filter_map(|(index, item)|
        (has(item, "start") && item.paths.iter().any(|name| name == "CommandWindow"))
            .then_some(index)).collect();
    if starts.len() != 1 || !(starts[0] < call && phases[0] < call && call < finish
        && call < phases[1] && call < proof && finish < hook && phases[1] < hook
        && proof < hook) { return false; }
    if !observed[call].fields.iter().any(|name| name == "storage")
        || !has(&observed[call], "map_err")
        || !observed[call].paths.iter().any(|name| name == "status")
        || !has(&observed[starts[0]], "diagnostic_time_100ns")
        || !has(&observed[finish], "diagnostic_time_100ns")
        || observed.iter().any(latest_global) { return false; }
    for index in [phases[0], phases[1], proof] {
        if !observed[index].fields.iter().any(|name| name == "storage") { return false; }
    }
    let Some(result) = local_name(&block.stmts[call]) else { return false; };
    let Some(Stmt::Expr(Expr::Path(tail), None)) = block.stmts.last() else { return false; };
    if !tail.path.is_ident(&result) { return false; }
    for index in [call, phases[0], phases[1], proof, finish] {
        let Some(name) = local_name(&block.stmts[index]) else { return false; };
        if !observed[hook].paths.contains(&name) { return false; }
    }
    ["mount", "journal_bytes"].iter()
        .all(|field| observed[hook].fields.iter().any(|name| name == field))
}

#[test]
fn journal_captures_exact_lease_and_journal_extent_before_storage_move() {
    let file = source("writable_fs/registry_journal.rs").unwrap();
    let fields = file.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "Journal" => Some(&item.fields),
        _ => None,
    }).unwrap();
    for field in ["mount", "journal_bytes"] {
        assert!(fields.iter().any(|item| item.ident.as_ref().is_some_and(|name| name == field)),
            "Journal retains copied {field}, not a later global lookup");
    }
    let body = method(&file, "admit");
    let items: Vec<_> = body.stmts.iter().map(effects).collect();
    let storage = items.iter().position(|item| has(item, "open") && has(item, "create"))
        .expect("actual existing/create storage move");
    let mount = items.iter().position(|item| has(item, "identity")
        && item.paths.iter().any(|name| name == "device"))
        .expect("capture the acquired device lease identity");
    let bytes = items.iter().position(|item| has(item, "len")
        && item.paths.iter().any(|name| name == "journal"))
        .expect("capture the owned journal length");
    assert!(mount < storage && bytes < storage);
    assert!(!items.iter().any(latest_global));
}

#[test]
fn journal_attempt_observation_preserves_result_and_uses_direct_storage_proof() {
    let file = source("writable_fs/registry_journal.rs").unwrap();
    assert!(attempt_contract(&method(&file, "make_durable")),
        "observe exact storage phases/result/proof around one CommandWindow without replacing the result");
}

#[test]
fn checkpoint_audit_is_bounded_allocation_free_and_observation_only() {
    let file = source("registry_checkpoint_audit.rs")
        .expect("focused checkpoint observation module is wired, not a dormant comment");
    let mut observed = Effects::default();
    observed.visit_file(&file);
    assert!(file.items.iter().any(|item| matches!(item, Item::Fn(function)
        if function.sig.ident == "system_journal")));
    for required in ["claim", "print_record"] { assert!(has(&observed, required)); }
    assert!(observed.paths.iter().any(|name| name == "ReceiptBudget"));
    assert!(observed.paths.iter().any(|name| name == "RecordBuffer"));
    assert!(!latest_global(&observed));
    for forbidden in ["format", "collect", "to_owned", "to_vec", "to_string", "reserve",
        "try_reserve", "Box", "Vec", "String", "read_volatile", "read_unaligned",
        "io_manager_mut", "resolve_registry_key", "writable_fs", "ensure_mounted",
        "commit_volume_snapshot", "make_durable", "call_on4_raw", "send", "reply",
        "ahci_read_sectors", "ahci_write_sectors", "current_process_id"] {
        assert!(!observed.calls.iter().chain(&observed.paths).any(|name| name == forbidden),
            "checkpoint observation cannot perform {forbidden}");
    }
}

#[test]
fn contract_rejects_omitted_hook_substituted_result_and_global_latest_proof() {
    let valid = r#"{
        let before = self.storage.phase();
        let window = CommandWindow::start(&AHCI_CENSUS, diagnostic_time_100ns());
        let result = self.storage.make_durable().map_err(status);
        let delta = window.finish(diagnostic_time_100ns());
        let after = self.storage.phase();
        let proof = self.storage.durability().map(|p| (p.snapshot_generation(), p.snapshot_bytes()));
        registry_checkpoint_audit::system_journal(self.mount, self.journal_bytes,
            before, after, proof, result, delta);
        result
    }"#;
    assert!(attempt_contract(&syn::parse_str(valid).unwrap()));
    for invalid in [
        valid.replace("system_journal", "omitted_hook"),
        valid.replace("\n        result\n", "\n        Ok(())\n"),
        valid.replace("self.storage.durability()", "WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.load()"),
    ] {
        assert!(!attempt_contract(&syn::parse_str(&invalid).unwrap()));
    }
}
