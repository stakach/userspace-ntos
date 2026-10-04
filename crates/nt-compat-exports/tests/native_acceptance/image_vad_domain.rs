//! Native image placement must use the complete user VAD authority. Private allocation limits
//! remain caller policy, not an implicit rejection of otherwise valid PE preferred addresses.

use syn::visit::Visit;

const MAIN: &str = include_str!("../../../../components/ntos-executive/src/main.rs");

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        })
        .unwrap_or_else(|| panic!("actual native function {name} must exist"))
}

fn value(file: &syn::File, expression: &syn::Expr) -> u64 {
    match expression {
        syn::Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(integer) => integer.base10_parse().unwrap(),
            _ => panic!("VAD boundary must be an integer"),
        },
        syn::Expr::Path(path) => {
            let name = &path.path.segments.last().unwrap().ident;
            let constant = file
                .items
                .iter()
                .find_map(|item| match item {
                    syn::Item::Const(item) if item.ident == *name => Some(item),
                    _ => None,
                })
                .expect("VAD boundary must resolve to an actual native constant");
            value(file, &constant.expr)
        }
        syn::Expr::Paren(expression) => value(file, &expression.expr),
        _ => panic!("unsupported VAD boundary expression; review the actual domain contract"),
    }
}

#[derive(Default)]
struct Constructors<'ast> {
    factory_calls: usize,
    raw: Vec<&'ast syn::ExprCall>,
}

impl<'ast> Visit<'ast> for Constructors<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if path.path.is_ident("new_process_vm_region_map") {
                self.factory_calls += 1;
            }
            if path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "VmRegionMap")
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "new")
            {
                self.raw.push(call);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn native_process_vad_authority_covers_the_full_image_user_domain() {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let factory = function(&file, "new_process_vm_region_map");
    let mut constructors = Constructors::default();
    constructors.visit_block(&factory.block);
    assert_eq!(
        constructors.raw.len(),
        1,
        "one authoritative process VAD constructor"
    );
    let args = &constructors.raw[0].args;
    assert_eq!(args.len(), 2);
    let lower = value(&file, &args[0]);
    let upper = value(&file, &args[1]);
    let user_limit: syn::Expr = syn::parse_str("USER_ADDRESS_LIMIT").unwrap();
    assert_eq!(lower, 0, "retain the existing complete lower VAD domain");
    assert_eq!(
        upper,
        value(&file, &user_limit),
        "image VAD authority must not clamp valid preferred addresses to PRIVATE_VM_LIMIT"
    );
    assert!(upper > 0x0000_07ff_b600_0000 + 0x2b_1000);
}

#[test]
fn all_native_process_vad_initialization_and_scratch_use_the_same_factory() {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    for name in [
        "reset_process_vm_region_maps",
        "process_vm_region_map_reset",
    ] {
        let mut constructors = Constructors::default();
        constructors.visit_block(&function(&file, name).block);
        assert_eq!(
            constructors.factory_calls, 1,
            "{name} must use the canonical factory"
        );
        assert!(
            constructors.raw.is_empty(),
            "{name} must not reintroduce a private-only domain"
        );
    }
    for name in ["VM_MAP_BEFORE", "VM_MAP_AFTER"] {
        let item = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Static(item) if item.ident == name => Some(item),
                _ => None,
            })
            .expect("actual native VAD scratch must exist");
        let mut constructors = Constructors::default();
        constructors.visit_expr(&item.expr);
        assert_eq!(
            constructors.factory_calls, 1,
            "{name} must use the canonical factory"
        );
        assert!(constructors.raw.is_empty());
    }
}
