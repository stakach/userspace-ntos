use syn::visit::Visit;

#[derive(Default)]
struct Methods(Vec<String>);
impl<'ast> Visit<'ast> for Methods {
    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.0.push(expression.method.to_string());
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn set_branch() -> syn::ExprMatch {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    struct Find(Option<syn::ExprMatch>);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            if expression.arms.iter().any(|arm| {
                matches!(&arm.pat, syn::Pat::Path(path)
                    if path.path.segments.last().is_some_and(|part| part.ident == "NtSetInformationFile"))
            }) {
                self.0 = Some(expression.clone());
            }
            syn::visit::visit_expr_match(self, expression);
        }
    }
    let mut find = Find(None);
    find.visit_file(&file);
    find.0.expect("native SET_INFORMATION dispatcher")
}

#[test]
fn native_mode_set_is_intercepted_after_capture_before_any_filesystem_set() {
    let expression = set_branch();
    let arm = expression.arms.iter().find(|arm| {
        matches!(&arm.pat, syn::Pat::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "NtSetInformationFile"))
    }).unwrap();
    let mut methods = Methods::default();
    methods.visit_expr(&arm.body);
    let position = |name: &str| methods.0.iter().position(|method| method == name)
        .unwrap_or_else(|| panic!("native mode SET requires {name}"));
    assert!(position("probe_user_input") < position("try_set_file_mode_information"));
    assert!(position("capture_hosted_file_unless_local_with_access")
        < position("try_set_file_mode_information"));
    assert!(position("try_set_file_mode_information") < position("set_hosted_file_information"));
    assert!(position("try_set_file_mode_information") < position("try_set_local_file_information"));
}

#[test]
fn native_mode_commit_uses_canonical_body_and_serialized_completion_policy() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_file_mode.rs");
    let source = std::fs::read_to_string(path).expect("focused native File mode boundary");
    let file = syn::parse_file(&source).unwrap();
    let mut methods = Methods::default();
    methods.visit_file(&file);
    assert!(methods.0.iter().any(|method| method == "update_io_mode_with"),
        "completion policy must preflight serialization before the memory-only commit");
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*expression.func {
                self.0.push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, expression);
        }
    }
    let mut calls = Calls(Vec::new());
    calls.visit_file(&file);
    assert!(methods.0.iter().chain(calls.0.iter()).any(|name| name == "set_owned_file_mode"),
        "the canonical body transition, not a projection-only flag write, owns mode");
    struct ClosureEffects(Vec<String>);
    impl<'ast> Visit<'ast> for ClosureEffects {
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.method == "update_io_mode_with" {
                for argument in &expression.args {
                    if let syn::Expr::Closure(closure) = argument {
                        let mut methods = Methods::default();
                        methods.visit_expr(&closure.body);
                        self.0.extend(methods.0);
                        let mut calls = Calls(Vec::new());
                        calls.visit_expr(&closure.body);
                        self.0.extend(calls.0);
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, expression);
        }
    }
    let mut effects = ClosureEffects(Vec::new());
    effects.visit_file(&file);
    assert!(!effects.0.iter().any(|name| matches!(name.as_str(),
        "call_on4_raw" | "dispatch_hosted_file_irp_for" | "dispatch_hosted_file_set_information_for"
        | "publish_hosted_file_mode")),
        "native projection effects cannot execute inside the memory-only policy commit");
}
