use syn::{visit::Visit, ImplItem, Item};

#[derive(Default)]
struct QueryVolumeMajor(bool);

impl<'ast> Visit<'ast> for QueryVolumeMajor {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.0 |= path.path.segments.last().is_some_and(|segment| {
            segment.ident == "IRP_MJ_QUERY_VOLUME_INFORMATION"
        });
        syn::visit::visit_expr_path(self, path);
    }
}

#[test]
fn mounted_native_volume_routes_query_volume_to_its_filesystem_backend() {
    let mount = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume.rs"
    ))
    .unwrap();
    let registration = mount.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "register_mounted_volume" => Some(function),
        _ => None,
    }).expect("mounted volume registration");
    let mut major = QueryVolumeMajor::default();
    major.visit_block(&registration.block);
    assert!(major.0,
        "mounted Native volume must publish IRP_MJ_QUERY_VOLUME_INFORMATION for autochk FileFsAttributeInformation");

    let backend = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume_backend.rs"
    ))
    .unwrap();
    let dispatch = backend.items.iter().find_map(|item| match item {
        Item::Impl(implementation) => implementation.items.iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == "dispatch_irp" => Some(function),
            _ => None,
        }),
        _ => None,
    }).expect("mounted filesystem dispatch");
    let mut arm = QueryVolumeMajor::default();
    arm.visit_block(&dispatch.block);
    assert!(arm.0,
        "mounted Native volume must dispatch query-volume IRPs to its filesystem backend");
}
