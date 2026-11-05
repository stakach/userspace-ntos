//! The pinned LiberNT user32 callback table must reach the real client and
//! return its exact bytes and status through the native win32k bridge.

use nt_user_callback::{UserCallbackContract, NO_PAYLOAD_REFERENCE};
use syn::visit::{self, Visit};

fn function<'a>(source: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("missing native callback boundary {name}"))
}

fn calls(block: &syn::Block) -> Vec<String> {
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref() {
                if let Some(name) = path.path.segments.last() {
                    self.0.push(name.ident.to_string());
                }
            }
            visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut found = Calls::default();
    found.visit_block(block);
    found.0
}

fn has_call(block: &syn::Block, name: &str) -> bool {
    calls(block).iter().any(|call| call == name)
}

fn native_source(name: &str) -> syn::File {
    let source = match name {
        "win32k_glue.rs" => include_str!("../../../components/ntos-executive/src/win32k_glue.rs"),
        "win32k_subsystem.rs" => include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs"),
        _ => panic!("unexpected source {name}"),
    };
    syn::parse_file(source).unwrap()
}

#[test]
fn pinned_charset_and_ime_callbacks_are_admitted_without_synthetic_results() {
    // Pinned u32cb.h: GETCHARSETINFO=9, IMMLOADLAYOUT=19. callback.h and
    // IMEINFOEX define these exact x64 input/result sizes.
    for (api, input, result) in [(9, 36, 36), (19, 8, 360)] {
        let contract = UserCallbackContract::for_api(api)
            .unwrap_or_else(|| panic!("pinned user32 callback {api} is not admitted"));
        assert_eq!(contract.minimum_result_capacity(input), Some(result));
        assert!(contract.accepts_request(input, result, NO_PAYLOAD_REFERENCE));
        assert!(contract.accepts_result(input, result, 0));
        assert!(!contract.accepts_result(input, result - 1, 0));
    }
    // User32CallGetCharsetInfo returns the original 36-byte Arguments even
    // when TranslateCharsetInfo fails with STATUS_UNSUCCESSFUL.
    assert!(UserCallbackContract::for_api(9).unwrap()
        .accepts_result(36, 36, 0xc000_0001u32 as i32));
}

#[test]
fn native_component_and_root_route_these_callbacks_to_real_user32() {
    let component = native_source("win32k_subsystem.rs");
    let producer = function(&component, "s_ke_user_mode_callback_rendezvous");
    for required in ["for_api", "minimum_result_capacity", "begin_request", "validate_reply"] {
        assert!(has_call(&producer.block, required), "component callback lost {required}");
    }

    let root = native_source("win32k_glue.rs");
    let gate = function(&root, "client_callback_supported_for_api");
    assert!(has_call(&gate.block, "callback_client_runtime"),
        "real user32 dispatch must be gated by the registered client runtime");
    let dispatch = function(&root, "service_user_callback");
    for required in ["for_api", "accepts_request", "client_callback_supported_for_api",
        "begin_controlled_continuation"] {
        assert!(has_call(&dispatch.block, required), "root callback dispatch lost {required}");
    }
}

#[test]
fn native_completion_copies_bytes_and_publishes_actual_user32_status() {
    let root = native_source("win32k_glue.rs");
    let completion = function(&root, "complete_controlled_user_callback");
    assert!(has_call(&completion.block, "accepts_result"));
    assert!(has_call(&completion.block, "publish_callback_reply"));

    let publisher = function(&root, "publish_callback_reply");
    assert!(has_call(&publisher.block, "copy_callback_result_to_shared"),
        "the user32 result must be copied even when callback status is negative");
    assert!(has_call(&publisher.block, "validate_reply"));
    let source = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    let publisher_source = source.split("unsafe fn publish_callback_reply(").nth(1).unwrap()
        .split("fn user_callback_validation_error_name").next().unwrap();
    assert!(publisher_source.contains("reply.output_length = result_length as u32"));
    assert!(publisher_source.contains("reply.status = callback_status as i32"));
}
