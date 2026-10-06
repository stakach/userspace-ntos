//! NtOpenFile acquires a File; SEC_IMAGE owns image parsing and source lifetime.
//! These source contracts supplement retained-File tests, not native boot proof.
use syn::{visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn method(file: &syn::File, name: &str) -> syn::Block {
    file.items
        .iter()
        .find_map(|item| {
            let Item::Impl(implementation) = item else {
                return None;
            };
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == name => {
                    Some(function.block.clone())
                }
                _ => None,
            })
        })
        .expect("actual native File admission")
}

#[derive(Default)]
struct Effects {
    calls: Vec<String>,
    fields: Vec<String>,
}

impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }
}

#[test]
fn canonical_file_open_does_not_stage_or_relocate_a_dll() {
    let mut effects = Effects::default();
    effects.visit_block(&method(&source("exec_handler.rs"), "nt_open_file_service"));
    for forbidden in [
        "demand_load_dll_result",
        "pool_alloc",
        "load_file_to_pool",
        "apply_relocations_to_buf",
    ] {
        assert!(
            !effects.calls.iter().any(|name| name == forbidden),
            "File admission must not eagerly stage image bytes through {forbidden}"
        );
    }
    assert!(
        !effects.fields.iter().any(|name| name == "dll_pe_store"),
        "the opened File must not populate a parallel parsed-DLL owner"
    );
    for required in [
        "capture_file_object_attributes",
        "mint_disk_file_handle",
        "publish_file_create_result",
    ] {
        assert!(
            effects.calls.iter().any(|name| name == required),
            "preserve actual checked File admission through {required}"
        );
    }
}

#[test]
fn obsolete_demand_dll_loader_is_removed_not_left_as_an_alternate_route() {
    let file = source("fs_loader.rs");
    for item in &file.items {
        let name = match item {
            Item::Fn(value) => &value.sig.ident,
            Item::Enum(value) => &value.ident,
            Item::Struct(value) => &value.ident,
            _ => continue,
        };
        assert!(
            ![
                "demand_load_dll_result",
                "DemandLoadError",
                "DemandLoadResult",
                "open_dll_read_result",
                "open_cluster_read_result"
            ]
            .iter()
            .any(|obsolete| name == obsolete),
            "remove single-consumer eager DLL machinery: {name}"
        );
    }
    assert!(
        file.items
            .iter()
            .any(|item| matches!(item, Item::Fn(value) if value.sig.ident == "load_file_to_pool")),
        "bootstrap and actual driver staging retain their existing owner in this increment"
    );
}

#[test]
fn local_image_section_still_captures_from_the_exact_retained_file() {
    let file = source("file_image_section.rs");
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(value) if value.sig.ident == "submit_local_image_section" => Some(value),
            _ => None,
        })
        .expect("canonical local SEC_IMAGE admission");
    let mut effects = Effects::default();
    effects.visit_block(&function.block);
    let position = |name: &str| {
        effects
            .calls
            .iter()
            .position(|call| call == name)
            .unwrap_or_else(|| panic!("missing retained File operation {name}"))
    };
    assert!(position("retain_io") < position("capture_image_layout"));
    assert!(position("capture_image_layout") < position("reserve_local_native_image_section"));
    assert!(effects.calls.iter().any(|call| call == "read_exact"));
    assert!(!effects.calls.iter().any(|call| call == "load_file_to_pool"));
    assert!(effects.fields.iter().any(|field| field == "file_extent"));
}

#[test]
fn sam_acceptance_requires_database_evidence_not_staged_dll_bytes() {
    let file = source("main.rs");
    struct SamEvidence {
        obsolete: bool,
        gate: Option<Expr>,
    }
    impl<'ast> Visit<'ast> for SamEvidence {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.obsolete |= ident == "SAMSRV_LOADED_SIZE";
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(call.args.first(), Some(Expr::Lit(value))
                if matches!(&value.lit, syn::Lit::ByteStr(name)
                    if name.value() == b"exec_samsrv_hosted"))
            {
                assert!(self
                    .gate
                    .replace(call.args.iter().nth(1).unwrap().clone())
                    .is_none());
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut evidence = SamEvidence {
        obsolete: false,
        gate: None,
    };
    evidence.visit_file(&file);
    assert!(
        !evidence.obsolete,
        "staging bytes are not evidence of SAM execution"
    );
    struct Names(Vec<String>);
    impl<'ast> Visit<'ast> for Names {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.0.push(ident.to_string());
        }
    }
    let mut names = Names(Vec::new());
    names.visit_expr(&evidence.gate.expect("actual SAM acceptance gate"));
    for required in [
        "SAM_HIVE_SIZE",
        "SAM_HIVE_ROOT_OPENED",
        "sam_database_proven",
    ] {
        assert!(
            names.0.iter().any(|name| name == required),
            "preserve actual SAM database evidence {required}"
        );
    }
}
