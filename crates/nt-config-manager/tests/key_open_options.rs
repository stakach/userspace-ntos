use nt_config_manager::{validate_key_open_options, KeyOpenOptions};

#[test]
fn extended_key_open_options_carry_backup_and_open_link() {
    assert_eq!(validate_key_open_options(0), Ok(KeyOpenOptions::default()));
    assert_eq!(
        validate_key_open_options(4),
        Ok(KeyOpenOptions {
            backup: true,
            open_link: false
        })
    );
    assert_eq!(
        validate_key_open_options(8),
        Ok(KeyOpenOptions {
            backup: false,
            open_link: true
        })
    );
    assert_eq!(
        validate_key_open_options(0xc),
        Ok(KeyOpenOptions {
            backup: true,
            open_link: true
        })
    );
    assert_eq!(validate_key_open_options(1), Err(0xC000_000D));
    assert_eq!(validate_key_open_options(0x10), Err(0xC000_000D));
}
