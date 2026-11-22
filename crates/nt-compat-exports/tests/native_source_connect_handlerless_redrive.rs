//! A parked class CONNECT can redrive while the outer AddDevice lacks a handler context.

#[test]
fn nested_connect_redrive_does_not_require_the_file_handler() {
    let source = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let input = &source[source.find("unsafe fn redrive_nested_hosted_input_work() -> bool {").unwrap()..];
    let input = &input[..input.find("\n}").unwrap()];
    assert!(input.contains("nested_hosted_connect_forward_ready()"));
    assert!(input.contains("redrive_nested_hosted_connect_forward()"));
    assert!(input.contains("nested_hosted_hook_forward_ready()"));
    assert!(input.contains("redrive_nested_hosted_hook_forward()"));
}
