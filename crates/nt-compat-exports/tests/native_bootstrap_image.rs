//! Installed bootstrap images must not be truncated to a fixed storage-host window.

use syn::{visit::Visit, Expr};

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.iter()
                .map(|segment| segment.ident.to_string()).collect::<Vec<_>>().join("::"));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn calls(source: &str) -> Calls {
    let parsed = syn::parse_file(source).expect("native source must parse");
    let mut calls = Calls::default();
    calls.visit_file(&parsed);
    calls
}

#[test]
fn rebuilt_ntdll_larger_than_two_mib_uses_a_full_owned_file_source() {
    // The rebuilt transport DLL that reproduced this failure was 2,171,904 bytes.
    assert!(2_171_904u32 > 512 * 4096);
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let storage = include_str!("../../../components/ntos-executive/src/storage_host.rs");
    let probe = include_str!("../../../components/ntos-executive/src/device_io.rs");
    let spawn = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    for source in [main, storage, probe, spawn] {
        assert!(!source.contains("NTDLLBUF"),
            "fixed ntdll staging cannot represent the rebuilt installed DLL");
    }
    assert!(calls(main).0.iter().any(|call| call == "bootstrap_image::load_installed"),
        "bootstrap must obtain the complete installed file through owned dynamic storage");
    assert!(main.contains("exec_ntdll_loaded_from_fs_by_path"),
        "the full installed-file read must retain the genuine filesystem proof");
    assert!(!probe.contains("ntdll_dest"), "storage must not publish a truncated prefix as a file");
    assert!(!main.contains("(verdict & 0x100)"),
        "the path proof must follow the complete root read, not storage directory lookup");
}

#[test]
fn bootstrap_source_uses_existing_persistent_exact_length_file_pool() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/bootstrap_image.rs");
    let source = std::fs::read_to_string(path)
        .expect("bootstrap image ownership must have a focused native module");
    let calls = calls(&source);
    assert!(calls.0.iter().any(|call| call.ends_with("::exec_fs")));
    assert!(calls.0.iter().any(|call| call.ends_with("::load_file_to_pool")));
    assert!(source.contains("source_va"), "relocation and fault fill must retain the actual source VA");
    assert!(!source.contains(".min("), "whole-file admission must not cap the directory length");
    assert!(!source.contains("NTDLLBUF"));
}
