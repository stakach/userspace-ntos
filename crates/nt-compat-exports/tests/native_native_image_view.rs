use syn::visit::Visit;

#[derive(Default)]
struct MapViewArm<'a>(Option<&'a syn::Arm>);
impl<'a> Visit<'a> for MapViewArm<'a> {
    fn visit_arm(&mut self, arm: &'a syn::Arm) {
        if matches!(&arm.pat, syn::Pat::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "NtMapViewOfSection"))
        {
            assert!(self.0.replace(arm).is_none(), "ambiguous live MapView arm");
        }
        syn::visit::visit_arm(self, arm);
    }
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn canonical_image_view_routes_before_generic_data_section_lookup() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_handler.rs"
    ))
    .unwrap();
    let mut arm = MapViewArm::default();
    arm.visit_file(&source);
    let mut calls = Calls::default();
    calls.visit_expr(&arm.0.expect("live NtMapViewOfSection dispatch").body);
    let canonical = calls
        .0
        .iter()
        .position(|call| call == "map_native_image_section_view")
        .expect("canonical SEC_IMAGE handles need their own retained view route");
    let generic = calls
        .0
        .iter()
        .position(|call| call == "section")
        .expect("existing generic data-section route remains available");
    assert!(canonical < generic,
        "tagged canonical image IDs must not be interpreted as generic section indices");
}
