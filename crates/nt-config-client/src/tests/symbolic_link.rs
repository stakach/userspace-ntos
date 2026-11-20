use super::*;

const LINK: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Print\Printers";
const TARGET: &str = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers";

fn hive_with_link() -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 1);
    let link = hive.create_key(r"ControlSet001\Control\Print\Printers");
    assert!(hive.set_key_kind(link, nt_hive_core::KeyKind::SymbolicLink));
    hive.set_value(link, "SymbolicLinkValue", RegistryValueType::Link,
        TARGET.encode_utf16().flat_map(u16::to_le_bytes).collect());
    secure_fixture_hive(&mut hive);
    hive.finish_clean_import();
    hive
}

fn open(client: &mut ConfigClient<Direct>, path: &str, open_link: bool)
    -> (SystemHiveKeyOpenAttempts, SystemHiveKeyOpenAttempt)
{
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve_with_options(None, path, open_link).unwrap();
    for operation in [
        SystemHiveKeyOpenOperation::Query,
        SystemHiveKeyOpenOperation::Begin,
        SystemHiveKeyOpenOperation::Acknowledge,
    ] {
        let mut exchange = manager.begin_exchange(&mut attempt, operation).unwrap();
        let response = client.exchange_system_hive_key_open(&exchange);
        manager.complete_exchange(&mut attempt, &mut exchange, response).unwrap();
    }
    (manager, attempt)
}

#[test]
fn an_open_through_a_link_is_a_validated_reparse_without_a_lease() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive_with_link())).unwrap();
    let (mut manager, mut attempt) = open(&mut client, &format!(r"{LINK}\HP"), false);
    assert_eq!(attempt.outcome_status(), Some(nt_config_abi::CM_STATUS_REPARSE));
    assert_eq!(attempt.reparse_target(), Some(format!(r"{TARGET}\HP").as_str()));
    assert_eq!(attempt.known_lease(), None);
    assert_eq!(manager.take_validated(&mut attempt, 1).err(), Some(nt_config_abi::CM_STATUS_REPARSE));
    manager.release(&mut attempt).unwrap();
}

#[test]
fn open_link_acquires_the_link_key_itself() {
    let mut client = client();
    client.import_system_hive(&encode_image(&hive_with_link())).unwrap();
    let (mut manager, mut attempt) = open(&mut client, LINK, true);
    assert_eq!(attempt.outcome_status(), Some(0));
    assert_eq!(attempt.reparse_target(), None);
    let generation = attempt.known_lease().unwrap().opened_generation;
    let opened = manager.take_validated(&mut attempt, generation).unwrap();
    manager.release(&mut attempt).unwrap();
    assert_eq!(opened.physical_path, r"\Registry\Machine\System\ControlSet001\Control\Print\Printers");
    let link = client.query_leased_system_hive_value(opened.lease, "SymbolicLinkValue").unwrap();
    assert_eq!(link.value_type, RegistryValueType::Link as u32);
    retained_test_keys::close(&mut client, opened.lease).unwrap();
}

const HARDWARE_LINK: &str = r"\Registry\Machine\HARDWARE\DEVICEMAP\Link";
const HARDWARE_TARGET: &str = r"\Registry\Machine\HARDWARE\DESCRIPTION\System";

#[test]
fn a_runtime_link_is_created_and_followed_through_the_cm_protocol() {
    let mut client = client();
    let parent = client.create_key(r"\Registry\Machine\HARDWARE\DEVICEMAP").unwrap();
    let snapshot = client.query_key_security_snapshot(r"\Registry\Machine\HARDWARE\DEVICEMAP").unwrap();
    let (link, created) = client.create_secured_key_of_kind(HARDWARE_LINK, &snapshot.descriptor,
        true, true, parent, snapshot.generation, None).unwrap();
    assert!(created);
    assert_eq!(client.create_secured_key_of_kind(HARDWARE_LINK, &snapshot.descriptor, true, true,
        parent, snapshot.generation, None), Err(0xC000_0035u32 as i32), "a link is never reopened");
    // Only the REG_LINK target may be set on it.
    let target: Vec<u8> = HARDWARE_TARGET.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(client.runtime_key_operation(link, nt_config_abi::runtime_key_op::SET_VALUE, 0,
        "Other", RegistryValueType::Sz as u32, &target).err(), Some(0xC000_0022u32 as i32));
    client.runtime_key_operation(link, nt_config_abi::runtime_key_op::SET_VALUE, 0,
        "SymbolicLinkValue", RegistryValueType::Link as u32, &target).unwrap();
    assert_eq!(client.open_key_id_following(&format!(r"{HARDWARE_LINK}\Bus"), false),
        Ok(RuntimeKeyOpen::Reparse(format!(r"{HARDWARE_TARGET}\Bus"))));
    assert_eq!(client.open_key_id_following(HARDWARE_LINK, true), Ok(RuntimeKeyOpen::Key(link)));
    assert_eq!(client.open_runtime_relative(parent, "Link", false),
        Ok(RuntimeKeyOpen::Reparse(HARDWARE_TARGET.into())));
    assert_eq!(client.open_runtime_relative(parent, "Link", true), Ok(RuntimeKeyOpen::Key(link)));
    assert_eq!(client.open_key_id(HARDWARE_LINK), Err(nt_config_abi::CM_STATUS_REPARSE));
}
