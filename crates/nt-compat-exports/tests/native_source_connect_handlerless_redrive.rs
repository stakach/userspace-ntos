//! A parked class CONNECT can redrive while the outer AddDevice lacks a handler context.

#[test]
fn nested_connect_redrive_does_not_require_the_file_handler() {
    let source = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let runner = &source[source.find("pub(crate) unsafe fn redrive_nested_hosted_file_work() -> bool {").unwrap()..];
    let guard = &runner[..runner.find("// Check each owner just before entering its runner.").unwrap()];
    assert!(guard.contains("if handler.is_null()"));
    assert!(guard.contains("redrive_nested_hosted_input_work()"),
        "handler-free CONNECT must run before the handler-required early return");

    let input = &source[source.find("unsafe fn redrive_nested_hosted_input_work() -> bool {").unwrap()..];
    let input = &input[..input.find("\n}").unwrap()];
    assert!(input.contains("nested_hosted_connect_forward_ready()"));
    assert!(input.contains("redrive_nested_hosted_connect_forward()"));
    assert!(input.contains("nested_hosted_hook_forward_ready()"));
    assert!(input.contains("redrive_nested_hosted_hook_forward()"));
    assert!(runner.contains("nested_hosted_lower_pnp_ready()"),
        "handler-required PnP work keeps its existing owner gate");
}
