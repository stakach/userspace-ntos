use super::*;

pub(super) fn append(
    journal: &mut Vec<u8>,
    parent: &str,
    name: &str,
    class_name: Option<&str>,
    descriptor: &[u8],
    volatile: bool,
) -> Result<(), i32> {
    append_inner(journal, parent, 0, name, class_name, descriptor, volatile)
}

pub(super) fn append_leased(
    journal: &mut Vec<u8>, parent: SystemHiveKeyLease, name: &str,
    class_name: Option<&str>, descriptor: &[u8], volatile: bool,
) -> Result<(), i32> {
    if parent.token == 0 || parent.opened_generation == 0 { return Err(STATUS_INVALID_PARAMETER); }
    append_inner(journal, "", parent.token, name, class_name, descriptor, volatile)
}

fn append_inner(
    journal: &mut Vec<u8>, parent: &str, lease: u64, name: &str,
    class_name: Option<&str>, descriptor: &[u8], volatile: bool,
) -> Result<(), i32> {
    use nt_config_abi::hive_create_child_metadata as metadata;
    if name.is_empty() || name.contains(['\\', '\0']) || descriptor.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let class = class_name
        .map(|class| checked_mutation_utf16(class, CM_MAX_HIVE_VALUE_NAME_UNITS))
        .transpose()?;
    let class_bytes = class.as_deref().unwrap_or(&[]);
    let descriptor_len = u32::try_from(descriptor.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let len = metadata::HEADER_BYTES
        .checked_add(if lease == 0 { 0 } else { 8 })
        .ok_or(STATUS_INVALID_PARAMETER)?
        .checked_add(class_bytes.len())
        .and_then(|len| len.checked_add(descriptor.len()))
        .ok_or(STATUS_INVALID_PARAMETER)?;
    u32::try_from(len).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let mut data = Vec::new();
    data.try_reserve_exact(len)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    if lease != 0 { data.extend_from_slice(&lease.to_le_bytes()); }
    data.extend_from_slice(&metadata::header(class_bytes.len() as u32, descriptor_len));
    data.extend_from_slice(class_bytes);
    data.extend_from_slice(descriptor);
    append_hive_mutation_record(
        journal,
        if lease == 0 { hive_mutation_kind::CREATE_CHILD } else { hive_mutation_kind::CREATE_CHILD_LEASED },
        (if class_name.is_some() {
            hive_mutation_flags::CLASS_PRESENT
        } else {
            0
        }) | if volatile { hive_mutation_flags::VOLATILE } else { 0 },
        0,
        parent,
        name,
        &data,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatility_is_explicit_for_path_and_leased_child_creation() {
        for volatile in [false, true] {
            for class_name in [None, Some(""), Some("class")] {
                for leased in [false, true] {
                    let mutation = if leased {
                        SystemHiveMutation::CreateChildRelative {
                            parent: SystemHiveKeyLease { token: 17, opened_generation: 9 },
                            name: "Child", class_name, descriptor: b"security", volatile,
                        }
                    } else {
                        SystemHiveMutation::CreateChild {
                            parent: "Parent", name: "Child", class_name,
                            descriptor: b"security", volatile,
                        }
                    };
                    let encoded = encode_hive_mutation_journal(&[mutation]).unwrap();
                    assert_eq!(u16::from_le_bytes(encoded[..2].try_into().unwrap()),
                        if leased { hive_mutation_kind::CREATE_CHILD_LEASED } else { hive_mutation_kind::CREATE_CHILD });
                    let flags = u16::from_le_bytes(encoded[2..4].try_into().unwrap());
                    assert_eq!(flags & hive_mutation_flags::VOLATILE != 0, volatile);
                    assert_eq!(flags & hive_mutation_flags::CLASS_PRESENT != 0, class_name.is_some());
                    assert_eq!(flags & !(hive_mutation_flags::VOLATILE | hive_mutation_flags::CLASS_PRESENT), 0);
                    assert!(encoded.ends_with(b"security"));
                    if leased {
                        let token_offset = CM_HIVE_MUTATION_RECORD_HEADER_BYTES + "Child".encode_utf16().count() * 2;
                        assert_eq!(u64::from_le_bytes(encoded[token_offset..token_offset + 8].try_into().unwrap()), 17);
                    }
                }
            }
        }
    }
}
