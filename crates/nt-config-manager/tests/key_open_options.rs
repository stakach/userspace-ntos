use nt_config_manager::validate_key_open_options;

#[test]
fn extended_key_open_options_preserve_backup_and_reject_unimplemented_link() {
    assert_eq!(validate_key_open_options(0), Ok(false));
    assert_eq!(validate_key_open_options(4), Ok(true));
    assert_eq!(validate_key_open_options(8), Err(0xC000_00BB));
    assert_eq!(validate_key_open_options(1), Err(0xC000_000D));
    assert_eq!(validate_key_open_options(0x10), Err(0xC000_000D));
}
