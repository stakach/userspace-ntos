use syn::visit::Visit;

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing loader entry {name}"))
}

#[derive(Default)]
struct EntryAudit {
    selector: Option<Vec<syn::Expr>>,
    process_images: Vec<String>,
    calls: Vec<String>,
    paths: Vec<String>,
    peb_offsets: Vec<u64>,
    peb_capture: bool,
}

impl<'ast> Visit<'ast> for EntryAudit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
                if name.ident == "select_loader_entry" {
                    assert!(
                        self.selector.is_none(),
                        "capture entry authority exactly once"
                    );
                    self.selector = Some(call.args.iter().cloned().collect());
                }
                if name.ident == "ldrp_drive" {
                    self.process_images.push(match call.args.first() {
                        Some(syn::Expr::Path(path)) => {
                            path.path.segments.last().unwrap().ident.to_string()
                        }
                        _ => panic!("process initialization must use the selected image binding"),
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }
    fn visit_expr_binary(&mut self, value: &'ast syn::ExprBinary) {
        if matches!(&value.op, syn::BinOp::Add(_))
            && matches!(&*value.left, syn::Expr::Path(path) if path.path.is_ident("peb"))
        {
            if let syn::Expr::Lit(literal) = &*value.right {
                if let syn::Lit::Int(offset) = &literal.lit {
                    self.peb_offsets.push(offset.base10_parse().unwrap());
                }
            }
        }
        syn::visit::visit_expr_binary(self, value);
    }
    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        if value
            .path
            .segments
            .last()
            .is_some_and(|part| part.ident == "asm")
        {
            self.peb_capture |= value.tokens.to_string().contains("gs:[0x60]");
        }
        syn::visit::visit_macro(self, value);
    }
}

#[test]
fn native_loader_selection_captures_peb_image_and_ldr_authority() {
    let source = syn::parse_file(include_str!("../../nt-ntdll-dll/src/lib.rs")).unwrap();
    let mut audit = EntryAudit::default();
    audit.visit_block(&function(&source, "LdrpInitialize").block);
    assert!(
        audit.peb_capture,
        "capture this thread's actual PEB from GS"
    );
    assert!(
        audit.peb_offsets.contains(&0x10),
        "capture PEB.ImageBaseAddress"
    );
    assert!(audit.peb_offsets.contains(&0x18), "capture PEB.Ldr");
    let arguments = audit
        .selector
        .expect("native entry must invoke shared select_loader_entry");
    assert_eq!(arguments.len(), 5);
    for (argument, expected) in arguments.iter().zip(["peb", "image_base", "loader_data"]) {
        assert!(
            matches!(argument, syn::Expr::Path(path) if path.path.is_ident(expected)),
            "shared loader selection must consume captured {expected}"
        );
    }
    assert!(
        audit
            .calls
            .iter()
            .any(|name| name == "ldr_initialize_thread"),
        "an initialized process must retain genuine thread attachment"
    );
    assert!(
        audit.calls.iter().any(|name| name == "rtl_raise_status"),
        "invalid captured authority must fail, not silently skip initialization"
    );
}

#[test]
fn loader_policy_has_no_legacy_skip_or_reserved_image_authority() {
    let source = syn::parse_file(include_str!("../../nt-ntdll/src/loader/entry.rs")).unwrap();
    let variants = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Enum(item) if item.ident == "LoaderEntry" => Some(&item.variants),
            _ => None,
        })
        .expect("shared loader selection result exists");
    assert_eq!(
        variants.len(),
        2,
        "valid loader entry is process initialization or thread attachment, never a skip"
    );
    assert!(variants
        .iter()
        .any(|variant| variant.ident == "InitializeProcess"));
    assert!(variants
        .iter()
        .any(|variant| variant.ident == "InitializeThread"));
    let selector = function(&source, "select_loader_entry");
    let reserved = match selector.sig.inputs.last().unwrap() {
        syn::FnArg::Typed(argument) => match &*argument.pat {
            syn::Pat::Ident(name) => name.ident.to_string(),
            _ => panic!("reserved argument has a named ABI slot"),
        },
        _ => panic!("loader selector has a reserved argument"),
    };
    let mut audit = EntryAudit::default();
    audit.visit_block(&selector.block);
    assert!(
        !audit.paths.iter().any(|name| name == &reserved),
        "reserved SystemArgument2/R8 must not select or override process image authority"
    );
    assert!(!audit.paths.iter().any(|name| name == "LegacySkip"));
}

#[test]
fn native_process_drive_never_uses_the_reserved_entry_argument() {
    let source = syn::parse_file(include_str!("../../nt-ntdll-dll/src/lib.rs")).unwrap();
    let entry = function(&source, "LdrpInitialize");
    let reserved = match entry.sig.inputs.last().unwrap() {
        syn::FnArg::Typed(argument) => match &*argument.pat {
            syn::Pat::Ident(name) => name.ident.to_string(),
            _ => panic!("native reserved ABI slot is named"),
        },
        _ => panic!("native entry has a reserved ABI slot"),
    };
    let mut audit = EntryAudit::default();
    audit.visit_block(&entry.block);
    assert_eq!(
        audit.process_images.len(),
        1,
        "native entry owns one genuine process initialization route"
    );
    assert_ne!(
        audit.process_images[0], reserved,
        "process image comes from selected PEB authority, not reserved R8"
    );
    assert!(!audit.paths.iter().any(|name| name == "LegacySkip"));
}
