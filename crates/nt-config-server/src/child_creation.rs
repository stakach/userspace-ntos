//! Checked copies for retained CM child mutations; class/security remain hive-owned metadata.

use super::{
    HiveTransaction, String, Vec, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

fn string(value: &str) -> Result<String, i32> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    copy.push_str(value);
    Ok(copy)
}

pub(super) fn path(parent: &str, name: &str) -> Result<String, i32> {
    validate_path(parent, name)?;
    let mut result = string(parent)?;
    result
        .try_reserve(
            name.len()
                .checked_add(1)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?,
        )
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    result.push('\\');
    result.push_str(name);
    Ok(result)
}

/// CM's query/open APIs must be able to address every child we publish. Apply this to physical
/// paths after alias normalization, not logical input whose length can legitimately differ.
pub(super) fn validate_path(parent: &str, name: &str) -> Result<(), i32> {
    let units = parent
        .encode_utf16()
        .count()
        .checked_add(1)
        .and_then(|units| units.checked_add(name.encode_utf16().count()))
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if units > nt_config_abi::CM_MAX_HIVE_PATH_UNITS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

pub(super) fn apply(
    tx: &mut HiveTransaction<'_>,
    parent: &str,
    name: &str,
    class: Option<&str>,
    descriptor: &[u8],
) -> Result<(), i32> {
    let parent = tx.open_key(parent).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let name = string(name)?;
    let class = class.map(string).transpose()?;
    let mut security = Vec::new();
    security
        .try_reserve_exact(descriptor.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    security.extend_from_slice(descriptor);
    tx.try_create_child(parent, name, class, security)
        .map(|_| ())
        .map_err(|error| {
            use nt_hive_core::CreateChildError;
            match error {
                CreateChildError::ParentNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
                CreateChildError::NameCollision => 0xc000_0035u32 as i32,
                CreateChildError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES,
                CreateChildError::InvalidName | CreateChildError::EmptySecurityDescriptor => {
                    STATUS_INVALID_PARAMETER
                }
            }
        })
}
