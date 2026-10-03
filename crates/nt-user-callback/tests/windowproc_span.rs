use nt_user_callback::windowproc_lparam_span;

#[test]
fn windowproc_lparam_span_matches_exact_reactos_callback_layout() {
    let mut payload = [0u8; 0x48];
    for size in [0i32, 1, 2, 7, 8] {
        payload[0x30..0x34].copy_from_slice(&size.to_le_bytes());
        let length = 0x40 + size as usize;
        assert_eq!(windowproc_lparam_span(&payload[..length]), Ok(Some(0x40..length)));
        assert!(windowproc_lparam_span(&payload[..length - 1]).is_err());
        if length < payload.len() {
            assert!(windowproc_lparam_span(&payload[..length + 1]).is_err());
        }
    }
    payload[0x30..0x34].copy_from_slice(&(-1i32).to_le_bytes());
    assert_eq!(windowproc_lparam_span(&payload[..0x40]), Ok(None));
    assert!(windowproc_lparam_span(&payload[..0x41]).is_err());
    for size in [-2i32, i32::MIN, i32::MAX] {
        payload[0x30..0x34].copy_from_slice(&size.to_le_bytes());
        assert!(windowproc_lparam_span(&payload[..0x40]).is_err());
    }
    assert!(windowproc_lparam_span(&payload[..0x30]).is_err());
}
