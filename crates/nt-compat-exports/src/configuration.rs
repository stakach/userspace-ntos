//! Allocation-free helpers for the NT loader configuration tree.

/// Test whether one `CONFIGURATION_COMPONENT` has the class, type, and optional key requested by
/// `KeFindConfigurationNextEntry`.
pub fn component_matches(
    component_class: u32,
    component_type: u32,
    component_key: u32,
    requested_class: u32,
    requested_type: u32,
    requested_key: Option<u32>,
) -> bool {
    component_class == requested_class
        && component_type == requested_type
        && requested_key.is_none_or(|key| component_key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_key_matches_the_nt_configuration_contract() {
        assert!(component_matches(3, 12, 7, 3, 12, None));
        assert!(component_matches(3, 12, 7, 3, 12, Some(7)));
        assert!(!component_matches(3, 12, 7, 3, 12, Some(8)));
        assert!(!component_matches(2, 12, 7, 3, 12, None));
        assert!(!component_matches(3, 11, 7, 3, 12, None));
    }
}
