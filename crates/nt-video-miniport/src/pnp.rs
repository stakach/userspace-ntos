//! PnP requests owned by VideoPort rather than by a display miniport.

/// VideoPort answers this query for its video device. Other relation types
/// remain on the registered driver stack.
pub fn owns_target_device_relation(
    video_port_initialized: bool,
    minor: u8,
    relation_type: Option<u32>,
) -> bool {
    video_port_initialized
        && minor == nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
        && relation_type == Some(nt_pnp_abi::TARGET_DEVICE_RELATION)
}

#[cfg(test)]
mod tests {
    use super::owns_target_device_relation;

    #[test]
    fn video_port_only_owns_the_target_relation_query() {
        assert!(owns_target_device_relation(
            true,
            nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            Some(nt_pnp_abi::TARGET_DEVICE_RELATION),
        ));
        assert!(!owns_target_device_relation(
            false,
            nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            Some(nt_pnp_abi::TARGET_DEVICE_RELATION),
        ));
        assert!(!owns_target_device_relation(
            true,
            nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            Some(nt_pnp_abi::BUS_RELATIONS),
        ));
        assert!(!owns_target_device_relation(
            true,
            nt_pnp_abi::IRP_MN_START_DEVICE,
            Some(nt_pnp_abi::TARGET_DEVICE_RELATION),
        ));
    }
}
