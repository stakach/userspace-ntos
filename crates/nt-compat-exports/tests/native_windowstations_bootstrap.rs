// The canonical Object Manager boot namespace includes this path. Native
// directory opens use the executive mirror and its security descriptors.
const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const SECURITY: &str = include_str!("../../../components/ntos-executive/src/exec_directory_security.rs");

#[test]
fn executive_mirror_has_the_canonical_windowstations_parent_chain() {
    let bootstrap = EXEC
        .split("fn build_initial_object_namespace()")
        .nth(1)
        .expect("native executive namespace bootstrap")
        .split("fn ascii_eq_ignore_case")
        .next()
        .unwrap();
    assert!(bootstrap.contains("b\"windows\""), "missing \\Windows parent");
    assert!(
        bootstrap.contains("b\"windowstations\", windows"),
        "missing \\Windows\\WindowStations child of \\Windows"
    );
    assert!(
        SECURITY.contains("b\"windows\"")
            && SECURITY.contains("b\"windowstations\"")
            && SECURITY.contains("Some(&inherited.descriptor)"),
        "both permanent directories need owned boot security descriptors"
    );
}
