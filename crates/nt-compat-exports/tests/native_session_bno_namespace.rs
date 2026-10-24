const SESSION: &str = include_str!("../../../components/ntos-executive/src/exec_session_namespace.rs");

#[test]
fn numbered_session_mirrors_the_owned_base_named_objects_child() {
    assert!(SESSION.contains("b\"basenamedobjects\", session"));
    assert!(SESSION.contains("canonical.base_named_objects.0"));
    assert!(SESSION.contains("descriptor: bno_descriptor"));
    assert!(SESSION.contains("base_named_objects: nt_types::ObjectId(bno_entry.payload)"));
    assert!(SESSION.contains("self.obj_ns[bno].unlink()"));
}
