use syn::{visit::Visit, Item};

struct Paths(Vec<String>);

struct MatchesArguments {
    expression: syn::Expr,
    pattern: syn::Pat,
    guard: Option<syn::Expr>,
}

impl syn::parse::Parse for MatchesArguments {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let expression = input.parse()?;
        input.parse::<syn::Token![,]>()?;
        let pattern = syn::Pat::parse_multi_with_leading_vert(input)?;
        let guard = if input.peek(syn::Token![if]) {
            input.parse::<syn::Token![if]>()?;
            Some(input.parse()?)
        } else {
            None
        };
        if input.peek(syn::Token![,]) { input.parse::<syn::Token![,]>()?; }
        Ok(Self { expression, pattern, guard })
    }
}

impl<'ast> Visit<'ast> for Paths {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.0.extend(path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_path(self, path);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("matches") {
            let arguments = syn::parse2::<MatchesArguments>(mac.tokens.clone())
                .expect("matches! arguments must be structurally parsed");
            let mut nested = Paths(Vec::new());
            nested.visit_expr(&arguments.expression);
            nested.visit_pat(&arguments.pattern);
            if let Some(guard) = &arguments.guard { nested.visit_expr(guard); }
            self.0.extend(nested.0);
        }
        syn::visit::visit_macro(self, mac);
    }
}

#[test]
fn mode_observer_receives_unclamped_terminal_information() {
    struct TerminalInformation(bool);
    impl<'ast> Visit<'ast> for TerminalInformation {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(function) = call.func.as_ref() {
                if function.path.segments.last().is_some_and(|part| part.ident == "observe_terminal") {
                    self.0 = call.args.len() == 6 && matches!(call.args.iter().nth(4),
                        Some(syn::Expr::Path(value)) if value.path.is_ident("information"));
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut observer = TerminalInformation(false);
    observer.visit_file(&syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_kernel_win32k_source_ioctl.rs")).unwrap());
    assert!(observer.0,
        "actual terminal Information must reach mode evidence before captured-length clamping can hide malformed output");
}
fn paths(source: &str) -> Vec<String> {
    let mut paths = Paths(Vec::new());
    paths.visit_file(&syn::parse_file(source).unwrap());
    paths.0
}

#[test]
fn real_eng_device_io_control_uses_native_irp_imports_without_a_private_transport() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let parsed = syn::parse_file(source).unwrap();
    for item in parsed.items {
        let name = match item {
            Item::Fn(item) => item.sig.ident.to_string(),
            Item::Const(item) => item.ident.to_string(),
            _ => continue,
        };
        assert!(!matches!(name.as_str(), "patch_eng_device_io_control" | "s_eng_device_io_control"
            | "request_video_device_io_control" | "service_video_device_io_control" | "W32_VIDEO_IOCTL_LABEL"),
            "obsolete EngDeviceIoControl bypass remains: {name}");
    }
}

#[test]
fn legacy_video_dispatch_cannot_bypass_the_retained_source_work() {
    let paths = paths(include_str!("../../../components/ntos-executive/src/spawn_hosts.rs"));
    assert!(!paths.iter().any(|name| name == "W32_VIDEO_IOCTL_LABEL"));
    assert!(!paths.iter().any(|name| name == "pump_service_video_device_io_control"));
}

#[test]
fn reserved_video_aperture_is_not_admitted_as_an_anonymous_private_fault() {
    let paths = paths(include_str!("../../../components/ntos-executive/src/spawn_hosts.rs"));
    assert!(paths.iter().any(|name| name == "is_reserved_win32k_video_aperture"),
        "reserved video aperture faults must be refused before generic private-page allocation");
}

#[test]
fn framebuffer_mode_observation_consumes_only_real_source_completion() {
    let source_text = include_str!("../../../components/ntos-executive/src/hosted_kernel_win32k_source_ioctl.rs");
    let source = paths(source_text);
    assert!(source.iter().any(|name| name == "observe_terminal"),
        "mode evidence must come from the actual completed IOCTL, not another injected query");
    let aperture = paths(include_str!("../../../components/ntos-executive/src/hosted_video_caller_aperture.rs"));
    for required in ["IOCTL_VIDEO_QUERY_CURRENT_MODE", "ModeEvidence", "observe",
        "publish_active_framebuffer_mode", "FB_BAR_PADDR"] {
        assert!(aperture.iter().any(|name| name == required),
            "actual mode observation must validate {required}");
    }
    let policy = paths(include_str!("../../nt-video-miniport/src/mode_evidence.rs"));
    assert!(policy.iter().any(|name| name == "parse_video_mode_information"),
        "shared mode evidence must retain the strict native record decoder");
    struct InputCapture(bool);
    impl<'ast> Visit<'ast> for InputCapture {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(function) = call.func.as_ref() {
                if function.path.segments.last().is_some_and(|part| part.ident == "observe_terminal") {
                    if let Some(syn::Expr::Reference(argument)) = call.args.iter().nth(3) {
                        if let syn::Expr::Field(field) = argument.expr.as_ref() {
                            self.0 = matches!(&field.member, syn::Member::Named(name) if name == "input")
                                && matches!(field.base.as_ref(), syn::Expr::Path(base) if base.path.is_ident("self"));
                        }
                    }
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut captured_input = InputCapture(false);
    captured_input.visit_file(&syn::parse_file(source_text).unwrap());
    assert!(captured_input.0, "successful SET evidence must use the retained request input");
}
