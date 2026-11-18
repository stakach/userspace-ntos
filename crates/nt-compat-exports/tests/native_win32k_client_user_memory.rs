//! win32k's user-mode memory is the attached client's private memory (#406).
//!
//! `EngAllocUserMem` returned a slot of a provider arena that no client VAD described, so
//! `EngSecureMem` was refused and every `DIB_CreateDIBSection` without a section failed.

fn win32k() -> &'static str {
    include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs")
}

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    source
        .split(name)
        .nth(1)
        .unwrap_or_else(|| panic!("{name} exists"))
        .split("\nextern \"win64\" fn ")
        .next()
        .unwrap()
}

#[test]
fn zw_virtual_memory_is_served_by_the_executive_in_the_client() {
    let source = win32k();
    let allocate = function(source, "extern \"win64\" fn s_zw_allocate_virtual_memory(");
    assert!(allocate.contains("VirtualMemoryRequest::Allocate"));
    assert!(allocate.contains("win32k_mm_broker_call("));
    let free = function(source, "extern \"win64\" fn s_zw_free_virtual_memory(");
    assert!(free.contains("VirtualMemoryRequest::Free"));
    assert!(free.contains("win32k_mm_broker_call("));
    for retired in ["uservm_alloc", "uservm_release", "WIN32K_USERVM_VADDR"] {
        assert!(!source.contains(retired), "provider user-memory arena {retired} remains");
    }
}

#[test]
fn executive_allocates_and_secures_against_the_same_client() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let broker = service
        .split("pub(crate) unsafe fn service_win32k_mm_request(")
        .nth(1)
        .expect("one win32k Mm broker")
        .split("\npub(crate) unsafe fn ")
        .next()
        .unwrap();
    let generation = broker
        .find("hosted_process_generation(pi) != Some(client_generation)")
        .expect("exact client generation");
    for service in [
        "service_win32k_secure_virtual_memory(",
        "service_win32k_unsecure_virtual_memory(",
        "service_win32k_allocate_virtual_memory(",
        "service_win32k_free_virtual_memory(",
    ] {
        let position = broker.find(service).unwrap_or_else(|| panic!("{service} brokered"));
        assert!(generation < position, "{service} runs only for the authenticated client");
    }
    let handler =
        include_str!("../../../components/ntos-executive/src/exec_win32k_virtual_memory.rs");
    for (name, native) in [
        (
            "fn service_win32k_allocate_virtual_memory(",
            "self.allocate_private_virtual_memory(",
        ),
        (
            "fn service_win32k_free_virtual_memory(",
            "self.free_private_virtual_memory(",
        ),
        (
            "fn service_win32k_secure_virtual_memory(",
            "validate_secure_range(",
        ),
    ] {
        let body = handler
            .split(name)
            .nth(1)
            .expect(name)
            .split("\n    pub(crate) ")
            .next()
            .unwrap();
        assert!(body.contains(native), "{name} uses {native}");
    }
    let native = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    for (syscall, core) in [
        (
            "fn nt_allocate_virtual_memory_with_user_memory(",
            "self.allocate_private_virtual_memory(",
        ),
        (
            "fn nt_free_virtual_memory(",
            "self.free_private_virtual_memory(",
        ),
    ] {
        let body = native.split(syscall).nth(1).expect(syscall).split("\n    }\n").next().unwrap();
        assert!(body.contains(core), "{syscall} shares {core} with win32k");
    }
}

#[test]
fn gdi_attributes_are_not_projected_from_a_shared_arena() {
    let glue = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    assert!(!glue.contains("fn map_gdi_user_attributes_into_client("));
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    assert!(!main.contains("WIN32K_USERVM"));
}

#[test]
fn win32k_vm_refusals_are_named_with_client_vad_occupancy() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let broker = service
        .split("pub(crate) unsafe fn service_win32k_mm_request(")
        .nth(1)
        .unwrap()
        .split("\npub(crate) unsafe fn ")
        .next()
        .unwrap();
    for trace in ["[win32k-alloc-refused]", "[win32k-free-refused]", "[win32k-secure-refused]"] {
        assert!(broker.contains(trace), "{trace} names the refused request");
    }
    assert!(broker.contains("extent_count()") && broker.contains("VM_REGION_CAPACITY"));
}

#[test]
fn gui_client_vad_tables_fit_win32k_user_memory_without_stack_snapshots() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let capacity: usize = main
        .split("const VM_REGION_CAPACITY: usize = ")
        .nth(1)
        .expect("VAD capacity")
        .split(';')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(capacity >= 256, "Explorer exhausted a {capacity}-extent table (#406)");
    // A table of this size must never be copied onto the bounded rootserver stack.
    for (file, source) in [
        ("hosted_stack_growth.rs", include_str!("../../../components/ntos-executive/src/hosted_stack_growth.rs")),
        ("exec_handler.rs", include_str!("../../../components/ntos-executive/src/exec_handler.rs")),
    ] {
        for copy in ["let before = *map;", "let mut candidate = before;", "let mut after = *map;"] {
            assert!(!source.contains(copy), "{file} copies a VmRegionMap onto the stack: {copy}");
        }
    }
    let address_space = include_str!("../../nt-address-space/src/lib.rs");
    assert!(!address_space.contains("let mut next = *self;"), "protect stages the whole map");
}
