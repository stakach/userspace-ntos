//! A SYSTEM key's change-notification name is the physical path the CM OPEN returns: the
//! executive arms a request with the watcher's `canon_path(physical_path)` and reports a committed
//! value change with the writer's `physical_path`. Handles reached through `CurrentControlSet`,
//! through the selected control set, absolutely or relative to the hive root, must name one key.

use super::*;
use nt_config_notify::{
    Armed, ChangeNotifier, KeyBody, REG_NOTIFY_CHANGE_LAST_SET, STATUS_NOTIFY_ENUM_DIR,
};

const PARAMETERS: &str = r"Services\WinSock2\Parameters";

fn selected_control_set_two() -> ConfigClient<Direct> {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    hive.set_dword(select, "Current", 2);
    hive.create_key(&format!(r"ControlSet001\{PARAMETERS}"));
    hive.create_key(&format!(r"ControlSet002\{PARAMETERS}"));
    hive.finish_clean_import();
    let mut client = client();
    assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
    client
}

fn armed(notifier: &mut ChangeNotifier<u32>, handle: u64, name: &str, tree: bool) {
    let body = KeyBody { process: 0x2C, handle };
    let armed = notifier.arm(body, name, REG_NOTIFY_CHANGE_LAST_SET, tree, 0x31C, handle as u32);
    assert!(matches!(armed, Ok(Armed::Pending(_))));
}

#[test]
fn current_control_set_watch_completes_on_a_change_through_the_selected_set() {
    let mut client = selected_control_set_two();
    let mut notifier = ChangeNotifier::new();
    let watched = retained_test_keys::open(
        &mut client, &format!(r"\Registry\Machine\System\CurrentControlSet\{PARAMETERS}"));
    armed(&mut notifier, 0x40, &nt_hive_core::canon_path(&watched.physical_path), false);

    let writer = retained_test_keys::open(
        &mut client, &format!(r"\REGISTRY\MACHINE\SYSTEM\controlset002\{PARAMETERS}"));
    let done = notifier.report_key_changed(&writer.physical_path, REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(done.iter().map(|done| (done.request, done.status)).collect::<Vec<_>>(),
        [(0x40, STATUS_NOTIFY_ENUM_DIR)]);

    // The control set that is not selected is a different key.
    let other = retained_test_keys::open(
        &mut client, &format!(r"\Registry\Machine\System\ControlSet001\{PARAMETERS}"));
    armed(&mut notifier, 0x44, &nt_hive_core::canon_path(&watched.physical_path), false);
    assert!(notifier.report_key_changed(&other.physical_path, REG_NOTIFY_CHANGE_LAST_SET).is_empty());
}

#[test]
fn relative_current_control_set_tree_watch_completes_on_an_absolute_writer() {
    let mut client = selected_control_set_two();
    let mut notifier = ChangeNotifier::new();
    let system = retained_test_keys::open(&mut client, r"\Registry\Machine\System");
    let services = retained_test_keys::open_relative(&mut client, system.lease, r"CurrentControlSet\Services");
    armed(&mut notifier, 0x48, &nt_hive_core::canon_path(&services.physical_path), true);

    let writer = retained_test_keys::open(
        &mut client, &format!(r"\Registry\Machine\System\CurrentControlSet\{PARAMETERS}"));
    let done = notifier.report_key_changed(&writer.physical_path, REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(done.iter().map(|done| (done.request, done.status)).collect::<Vec<_>>(),
        [(0x48, STATUS_NOTIFY_ENUM_DIR)]);
}
