//! The GDI image loader resolves cdd.dll against its own module-qualified
//! kernel registry. Its bindings must cover the released image's imports.

use nt_pe_loader::ImportRef;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use syn::visit::Visit;

const RELEASE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";
const CDD_SHA256: &str = "3c8eacb7583ffae9edad73c5f0f960cffc33cfbd8e4534421944a6118072ec37";
const CDD_KERNEL_IMPORTS: [&str; 6] = [
    "KeInitializeMutex",
    "KeInitializeSemaphore",
    "KeReleaseMutex",
    "KeReleaseSemaphore",
    "KeWaitForSingleObject",
    "RtlAssert",
];

#[test]
fn released_cdd_kernel_imports_bind_in_the_gdi_image_registry() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_path = root.join("rust-micro/vendor/libernt/manifest.txt");
    if manifest_path.exists() {
        let manifest = std::fs::read_to_string(manifest_path)
            .expect("pinned LiberNT release manifest");
        assert!(manifest.lines().any(|line| line == RELEASE_REVISION));
    }

    // The image is cached locally after release staging. CI still checks the
    // reviewed import inventory when release media is unavailable.
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/cdd.dll");
    if image.exists() {
        let bytes = std::fs::read(image).expect("released cdd.dll");
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), CDD_SHA256);
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("released cdd.dll PE");
        let imports: BTreeSet<String> = pe
            .imports()
            .expect("released cdd.dll imports")
            .into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .map(|entry| match entry {
                ImportRef::ByName { name, .. } => name,
                ImportRef::ByOrdinal { ordinal, .. } => {
                    panic!("released cdd.dll imports kernel ordinal {ordinal}")
                }
            })
            .collect();
        assert_eq!(imports, CDD_KERNEL_IMPORTS.map(str::to_owned).into_iter().collect());
    }

    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let source = syn::parse_file(source).expect("win32k host source");
    let register = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "register_trampolines" => Some(function),
        _ => None,
    }).expect("GDI image kernel export registry");
    struct Bindings(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "bind" && matches!(&*call.receiver, syn::Expr::Path(path)
                if path.path.is_ident("reg")) {
                if let Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(name), .. })) = call.args.first() {
                    self.0.insert(name.value());
                }
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut bindings = Bindings(BTreeSet::new());
    bindings.visit_block(&register.block);
    for name in CDD_KERNEL_IMPORTS {
        assert!(
            nt_compat_exports::module_export_descriptor("ntoskrnl.exe", name)
                .is_some_and(|descriptor| descriptor.status.is_available()),
            "module-qualified GDI image loader has no kernel export metadata for {name}"
        );
        assert!(bindings.0.contains(name), "GDI image loader cannot resolve cdd.dll import ntoskrnl.exe!{name}");
    }
}

#[test]
fn provider_sync_catalog_initializes_under_the_existing_metadata_guard() {
    let outer = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_subsystem.rs"
    )).unwrap();
    let outer = outer.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "initialize_provider_local_event_tracking" => Some(function),
        _ => None,
    }).unwrap();
    let inner = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_local_sync.rs"
    )).unwrap();
    let inner = inner.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "initialize_under_metadata" => Some(function),
        _ => None,
    }).unwrap();
    struct Calls { guard_acquires: usize, under_guard_initializers: usize }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let segments: Vec<_> = path.path.segments.iter().map(|part| part.ident.to_string()).collect();
                if segments.ends_with(&["ProviderMetadataGuard".into(), "acquire".into()]) {
                    self.guard_acquires += 1;
                }
                if segments.ends_with(&["local_sync".into(), "initialize_under_metadata".into()]) {
                    self.under_guard_initializers += 1;
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut outer_calls = Calls { guard_acquires: 0, under_guard_initializers: 0 };
    outer_calls.visit_block(&outer.block);
    assert_eq!(outer_calls.guard_acquires, 1);
    assert_eq!(outer_calls.under_guard_initializers, 1);
    let mut inner_calls = Calls { guard_acquires: 0, under_guard_initializers: 0 };
    inner_calls.visit_block(&inner.block);
    assert_eq!(inner_calls.guard_acquires, 0, "sync init must not reacquire the held metadata guard");
}

#[test]
fn root_sync_catalog_rollover_requires_complete_prior_generation_retirement() {
    let source = include_str!(
        "../../../components/ntos-executive/src/provider_dispatcher_backend.rs"
    );
    let function = source.split("unsafe fn sync_catalog_mut(").nth(1)
        .expect("root sync catalog entry point")
        .split("unsafe fn sync_catalog_for_lease(").next().unwrap();
    let check = function.find("validate_domain_retirement()")
        .expect("prior generation retirement check");
    let reset = function.find("*slot = None")
        .expect("retired catalog generation reset");
    assert!(check < reset, "sync catalog resets before retirement is proven");
    assert!(function.contains("win32k_provider_domain_is_current(provider)"),
        "root sync catalog must admit only the registered live provider");
}
