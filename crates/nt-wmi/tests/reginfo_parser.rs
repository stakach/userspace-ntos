use nt_wmi::reginfo::{parse_reginfo, RegInfoError};
use nt_wmi::WmiGuid;

fn reginfo(guid: [u8; 16], flags: u32) -> [u8; 56] {
    let mut bytes = [0u8; 56];
    bytes[0..4].copy_from_slice(&56u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..40].copy_from_slice(&guid);
    bytes[40..44].copy_from_slice(&flags.to_le_bytes());
    bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
    bytes
}

#[test]
fn parses_exact_x64_guid_registration() {
    let guid = [0x52; 16];
    let bytes = reginfo(guid, 0x40);
    let parsed = parse_reginfo(&bytes).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].guid, WmiGuid(guid));
    assert_eq!(parsed[0].flags, 0x40);
    assert_eq!(parsed[0].instance_count, 1);
}

#[test]
fn truncated_or_inconsistent_buffers_never_publish_partial_guid_sets() {
    let mut bytes = reginfo([0x52; 16], 0);
    assert_eq!(parse_reginfo(&bytes[..55]), Err(RegInfoError::Bounds));
    bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(parse_reginfo(&bytes), Err(RegInfoError::Bounds));
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[0..4].copy_from_slice(&60u32.to_le_bytes());
    assert_eq!(parse_reginfo(&bytes), Err(RegInfoError::Bounds));
}

#[test]
fn rejects_chained_reginfo_until_each_chain_link_has_an_owner() {
    let mut bytes = reginfo([0x52; 16], 0);
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(parse_reginfo(&bytes), Err(RegInfoError::Chained));
}
