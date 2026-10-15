//! The ReactOS input class drivers give RtlQueryRegistryValues a REG_SZ default
//! with DefaultLength == 0. That default is the device name used by win32k.

#[path = "../../../components/ntos-executive/src/hosted_registry_direct_default.rs"]
mod native_default;

#[test]
fn zero_length_string_defaults_publish_the_exact_input_class_names() {
    for base in ["KeyboardClass", "PointerClass"] {
        let units: Vec<u16> = base.encode_utf16().chain([0]).collect();
        let length = native_default::direct_default_length(1, 0, |index| {
            units.get(index).copied()
        });
        assert_eq!(length, Some(units.len() * 2));
    }
}

#[test]
fn unterminated_or_oversized_string_defaults_are_rejected() {
    assert_eq!(native_default::direct_default_length(1, 0, |_| Some(b'K' as u16)), None);
    assert_eq!(native_default::direct_default_length(1, 0, |_| None), None);
}

#[test]
fn explicit_expand_string_length_needs_no_terminator_scan() {
    assert_eq!(native_default::direct_default_length(2, 8, |_| panic!("unexpected scan")), Some(8));
}

#[test]
fn native_registry_query_uses_typed_string_default_publication() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let query = &source[source.find("extern \"win64\" fn s_rtl_query_registry_values(").unwrap()..];
    let query = &query[..query.find("\n}\n").unwrap()];
    assert!(query.contains("hosted_registry_direct_default::direct_default_length"));
    assert!(query.contains("write_rtl_direct_registry_value(default_type, data, entry_context)"));
    assert!(query.contains("copy_bytes_unchecked(entry_context, default_data, copy_len)"));
}
