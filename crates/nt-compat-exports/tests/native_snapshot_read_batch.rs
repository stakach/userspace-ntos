use syn::{Expr, ImplItem, Item, visit::Visit};

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs"
    ))
    .unwrap()
}

fn device_method(name: &str) -> syn::ImplItemFn {
    source()
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Impl(item)
                if item.trait_.as_ref().is_some_and(|(_, path, _)| {
                    path.segments.last().unwrap().ident == "SnapshotBlockDevice"
                }) =>
            {
                item.items.into_iter().find_map(|item| match item {
                    ImplItem::Fn(function) if function.sig.ident == name => Some(function),
                    _ => None,
                })
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("native SnapshotBlockDevice must override {name}"))
}

#[derive(Default)]
struct ReadWiring {
    paths: Vec<String>,
    methods: Vec<String>,
    effects: Vec<&'static str>,
    has_alignment_check: bool,
    has_failure_return: bool,
}

impl<'ast> Visit<'ast> for ReadWiring {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths
            .push(path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        if call.method == "checked_add" {
            self.effects.push("checked-end");
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        self.has_alignment_check |= matches!(binary.op, syn::BinOp::Rem(_));
        syn::visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            match path
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string()
                .as_str()
            {
                "ahci_read_sectors" => self.effects.push("read"),
                "ahci_read_sector" => self.effects.push("single-read"),
                "copy_nonoverlapping" => self.effects.push("copy"),
                _ => {}
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let mut condition = ReadWiring::default();
        condition.visit_expr(&expression.cond);
        if condition
            .paths
            .iter()
            .any(|path| path == "TASK_FILE_FAILURE")
        {
            assert!(
                expression
                    .then_branch
                    .stmts
                    .iter()
                    .any(|statement| { matches!(statement, syn::Stmt::Expr(Expr::Return(_), _)) }),
                "failed/partial AHCI command must return before exposing DMA bytes"
            );
            self.has_failure_return = true;
            self.effects.push("failure-return");
        }
        syn::visit::visit_expr_if(self, expression);
    }
}

#[test]
fn snapshot_native_batch_reads_use_bounded_ahci_and_copy_only_completed_chunks() {
    let mut wiring = ReadWiring::default();
    wiring.visit_impl_item_fn(&device_method("read_sectors"));
    assert!(
        wiring.has_alignment_check,
        "reject non-sector-sized output before DMA"
    );
    assert!(wiring.paths.iter().any(|path| path == "InvalidGeometry"));
    assert!(wiring.methods.iter().any(|method| method == "sector_size"));
    assert!(wiring.methods.iter().any(|method| method == "absolute_lba"));
    assert!(wiring.methods.iter().any(|method| method == "min"));
    assert!(
        wiring
            .paths
            .iter()
            .any(|path| path == "AHCI_MAX_SECTORS_PER_READ")
    );
    assert!(
        wiring
            .paths
            .iter()
            .any(|path| path == "AHCI_DMA_DATA_OFFSET")
    );
    assert!(wiring.has_failure_return);
    assert_eq!(
        wiring.effects,
        ["checked-end", "read", "failure-return", "copy"]
    );
}

#[test]
fn single_sector_snapshot_read_uses_the_same_validated_native_batch_path() {
    let mut wiring = ReadWiring::default();
    wiring.visit_impl_item_fn(&device_method("read_sector"));
    assert!(wiring.methods.iter().any(|method| method == "read_sectors"));
    assert!(
        wiring.effects.is_empty(),
        "single-sector adapter must not duplicate raw DMA effects"
    );
}

#[test]
fn snapshot_access_still_requires_the_exact_executable_mount_reserve_lease() {
    let function = source()
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "acquire" => Some(function),
            _ => None,
        })
        .unwrap();
    let mut wiring = ReadWiring::default();
    wiring.visit_item_fn(&function);
    assert!(wiring.methods.iter().any(|method| method == "try_acquire"));
    assert!(wiring.methods.iter().any(|method| method == "identity"));
    assert!(
        wiring
            .paths
            .iter()
            .any(|path| path == "exec_fs_mount_identity")
    );
    assert!(
        wiring
            .paths
            .iter()
            .any(|path| path == "STATUS_DEVICE_NOT_READY")
    );
}
