//! The autochk first pass asks the mounted filesystem for the real volume dirty state.

use syn::{visit::Visit, ImplItem, Item};

#[derive(Default)]
struct FsctlMajor(bool);

impl<'ast> Visit<'ast> for FsctlMajor {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.0 |= path.path.segments.last().is_some_and(|segment| {
            segment.ident == "IRP_MJ_FILE_SYSTEM_CONTROL"
        });
        syn::visit::visit_expr_path(self, path);
    }
}

#[derive(Default)]
struct ExactVolumeHandler {
    checks_binding: bool,
    checks_open_source: bool,
    requires_volume: bool,
    encodes_recorded_dirty_state: bool,
}

impl<'ast> Visit<'ast> for ExactVolumeHandler {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.checks_binding |= call.method == "binding";
        self.checks_open_source |= call.method == "get";
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.requires_volume |= path.path.segments.last().is_some_and(|segment| segment.ident == "Volume");
        self.encodes_recorded_dirty_state |= path.path.segments.last().is_some_and(|segment| segment.ident == "volume_dirty");
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        self.encodes_recorded_dirty_state |= matches!(&field.member, syn::Member::Named(name) if name == "volume_dirty");
        syn::visit::visit_expr_field(self, field);
    }
}

#[test]
fn mounted_volume_registers_filesystem_control_for_autochk() {
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume.rs"
    ))
    .unwrap();
    let register = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "register_mounted_volume" => Some(function),
        _ => None,
    }).expect("mounted volume registration");
    let mut major = FsctlMajor::default();
    major.visit_block(&register.block);
    assert!(major.0, "mounted volume must register IRP_MJ_FILE_SYSTEM_CONTROL so autochk's FSCTL_IS_VOLUME_DIRTY reaches its backend");
}

#[test]
fn mounted_volume_dispatches_filesystem_control_to_a_volume_handler() {
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume_backend.rs"
    ))
    .unwrap();
    let dispatch = source.items.iter().find_map(|item| match item {
        Item::Impl(implementation) => implementation.items.iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == "dispatch_irp" => Some(function),
            _ => None,
        }),
        _ => None,
    }).expect("mounted filesystem IRP dispatch");
    let mut major = FsctlMajor::default();
    major.visit_block(&dispatch.block);
    assert!(major.0, "mounted backend must dispatch IRP_MJ_FILE_SYSTEM_CONTROL rather than return STATUS_INVALID_DEVICE_REQUEST");
}

#[test]
fn mounted_dirty_fsctl_requires_exact_volume_file_and_recorded_state() {
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume_backend.rs"
    ))
    .unwrap();
    let handler = source.items.iter().find_map(|item| match item {
        Item::Impl(implementation) => implementation.items.iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == "filesystem_control" => Some(function),
            _ => None,
        }),
        _ => None,
    }).expect("mounted filesystem FSCTL handler");
    let mut checks = ExactVolumeHandler::default();
    checks.visit_block(&handler.block);
    assert!(checks.checks_binding && checks.checks_open_source && checks.requires_volume,
        "dirty FSCTL must require the exact generation-bound volume File, not any mounted ordinary File");
    assert!(checks.encodes_recorded_dirty_state,
        "dirty FSCTL must report the mounted BPB state, not a constant clean mask");
}

#[test]
fn native_acceptance_queries_dirty_on_the_case_sensitive_volume_file() {
    let probe = include_str!(
        "../../../../components/ntos-executive/src/mounted_volume_ingress_probe.rs"
    );
    let main = include_str!("../../../../components/ntos-executive/src/main.rs");
    let source = syn::parse_file(probe).unwrap();
    source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "run_volume_open" => Some(function),
        _ => None,
    }).expect("canonical case-sensitive volume File probe");
    assert!(probe.contains("opened_case_sensitive: true")
        && probe.contains("let dirty = query_volume_dirty(file, caller, expected_dirty)")
        && probe.contains("major::IRP_MJ_FILE_SYSTEM_CONTROL as u64")
        && probe.contains("nt_fs::FSCTL_IS_VOLUME_DIRTY as u64")
        && probe.contains("Ok((0, 4, None, _))"),
        "native probe must require successful four-byte FSCTL on the case-sensitive volume File");
    assert!(main.contains("exec_mounted_volume_fsctl_is_dirty")
        && main.contains("run_volume_open(device_id, fs.volume_dirty)"),
        "native boot check must compare returned mask against the mounted BPB dirty bit");
}
