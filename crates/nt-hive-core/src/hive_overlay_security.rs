//! Security admission for additive setup keys; raw data composition remains available.

use super::{CellId, Hive, HiveOverlayError};

pub(super) fn validate_explicit(descriptor: &[u8]) -> Result<(), HiveOverlayError> {
    nt_config_manager::validate_generated_key_security(descriptor)
        .map_err(|_| HiveOverlayError::InvalidSource)
}

pub(super) fn create_child(
    composed: &mut Hive,
    overlay: &Hive,
    source: CellId,
    parent: CellId,
    name: &str,
    volatile: bool,
    secured: bool,
) -> Result<CellId, HiveOverlayError> {
    if let Some(existing) = composed.open_subkey(parent, name) {
        return Ok(existing);
    }
    let descriptor = if secured {
        let parent_descriptor = composed.key_security_descriptor(parent)
            .ok_or(HiveOverlayError::InvalidSource)?;
        validate_explicit(parent_descriptor)?;
        match overlay.key_security_descriptor(source) {
            Some(explicit) => {
                validate_explicit(explicit)?;
                Some(explicit.to_vec())
            }
            None => {
                Some(nt_config_manager::inherit_generated_key_security(parent_descriptor)
                    .map_err(|_| HiveOverlayError::InvalidSource)?)
            }
        }
    } else {
        None
    };
    let child = composed.create_subkey_in_storage(
        parent, name, volatile || composed.is_volatile(parent),
    );
    if let Some(descriptor) = descriptor {
        if !composed.set_key_security_descriptor(child, &descriptor) {
            return Err(HiveOverlayError::InvalidSource);
        }
    }
    Ok(child)
}
