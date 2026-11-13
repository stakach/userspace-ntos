//! VM copy must classify a missing routed page before physical access, without inline I/O.

const RESIDENT: &str = include_str!(
    "../../../components/ntos-executive/src/exec_virtual_memory_resident.rs"
);
const FRAME_COPY: &str = include_str!(
    "../../../components/ntos-executive/src/img_spawn.rs"
);

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(name).expect("missing resident-only function");
    let open = start + source[start..].find('{').expect("function has a body");
    let mut depth = 0;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated resident-only function");
}

#[test]
fn copy_admission_routes_mapped_and_image_pages_before_provider_effects() {
    let admission = function_body(RESIDENT, "fn copy_page_admission(");
    assert!(RESIDENT.contains("enum CopyPageAdmission"));
    assert!(admission.contains("VmResidencySource::Mapped"));
    assert!(admission.contains("VmResidencySource::Image"));
    assert!(admission.contains("NeedsRoutedPageIn"));
    assert!(!admission.contains("routed_section_io::read("));
    assert!(!admission.contains("service_native_image_page_residency("));
}

#[test]
fn physical_one_page_copy_cannot_reenter_synchronous_residency() {
    for name in ["fn copy_read_resident_page(", "fn copy_write_resident_page("] {
        let body = function_body(RESIDENT, name);
        assert!(!body.contains("prepare_copy_page("), "{name} reenters preparation");
        assert!(!body.contains("ensure_residency_page("), "{name} can enter provider I/O");
        assert!(!body.contains("routed_section_io::read("), "{name} can enter provider I/O");
        assert!(!body.contains("service_native_image_page_residency("),
            "{name} can enter image I/O");
    }
}

#[test]
fn resident_write_alias_preserves_exact_process_generation() {
    let write = function_body(RESIDENT, "fn copy_write_resident_page(");
    let exact_copyout = function_body(FRAME_COPY, "fn client_copyout_mapped_admitted_for(");
    let frame_alias = function_body(FRAME_COPY, "fn recorded_frame_copyout_impl(");
    assert!(write.contains("client_copyout_mapped_admitted_for("));
    assert!(exact_copyout.contains("Some(process)"));
    assert!(frame_alias.contains("with_recorded_frame_alias(pi, process,"));
}
