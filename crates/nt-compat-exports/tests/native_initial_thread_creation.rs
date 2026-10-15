#[test]
fn initial_thread_selection_is_owned_by_the_canonical_lifetime_not_reusable_pi() {
    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let creation = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/initial_thread_creation.rs"
    ))
    .expect("focused initial-thread creation owner");
    for (name, source) in [
        ("handler", handler),
        ("main", main),
        ("service", service),
        ("creation", creation.as_str()),
    ] {
        assert!(
            !source.contains("PM_INITIAL_THREAD_DONE"),
            "{name}: a reusable PI bit cannot authorize initial-thread creation"
        );
    }
    assert!(
        handler.contains("create_foreign_thread"),
        "the syscall must use the focused foreign-thread admission path"
    );
    assert!(
        creation.contains("prepare_initial_thread_creation"),
        "the exact canonical main lifetime must reserve admission before native effects"
    );
    assert!(
        creation.contains("commit_initial_thread_creation"),
        "additional-thread selection requires acknowledged initial creation"
    );
    assert!(
        service.contains("handler.start_configured_initial_thread(primary_pi, main_tcb)"),
        "configured bootstrap startup must commit the same canonical creation receipt"
    );
    assert!(
        !service.contains("tcb_resume_r(main_tcb)"),
        "raw bootstrap resume cannot bypass canonical creation ownership"
    );
}
