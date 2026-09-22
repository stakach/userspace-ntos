use super::*;

pub(super) fn append(
    journal: &mut Vec<u8>,
    parent: &str,
    name: &str,
    class_name: Option<&str>,
    descriptor: &[u8],
) -> Result<(), i32> {
    append_inner(journal, parent, 0, name, class_name, descriptor)
}

pub(super) fn append_leased(
    journal: &mut Vec<u8>, parent: SystemHiveKeyLease, name: &str,
    class_name: Option<&str>, descriptor: &[u8],
) -> Result<(), i32> {
    if parent.token == 0 || parent.opened_generation == 0 { return Err(STATUS_INVALID_PARAMETER); }
    append_inner(journal, "", parent.token, name, class_name, descriptor)
}

fn append_inner(
    journal: &mut Vec<u8>, parent: &str, lease: u64, name: &str,
    class_name: Option<&str>, descriptor: &[u8],
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
        if class_name.is_some() {
            hive_mutation_flags::CLASS_PRESENT
        } else {
            0
        },
        0,
        parent,
        name,
        &data,
    )
}
