//! End to end over the names the executive actually forms. A request is armed with the name
//! `registry_target_path` gives its handle, and a change is reported with the name the mutation
//! path gives the changed key: for a mounted hive both are `MutableHiveSet::key_name` of the key
//! cell, for a read-only base-hive handle `MutableHiveSet::canonical_name` of its mount path and
//! hive-relative path, and `\registry\machine` for the `HKEY_LOCAL_MACHINE` root. The watchers are
//! the ones a ReactOS boot arms (ctfmon's `CRegWatcher`, mmdevapi's notification thread).

use nt_config_notify::{
    Armed, ChangeNotifier, Completion, KeyBody, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    STATUS_NOTIFY_ENUM_DIR,
};
use nt_hive_core::{Hive, HiveKind, MutableHiveSet, ResolvedHiveKey};

/// The executive's boot mounts (`hive_mount`, `HIVE_SEL_*`).
const SOFTWARE_HIVE: u32 = 0x2000_0000;
const SOFTWARE_MOUNT: &str = r"\Registry\Machine\SOFTWARE";
const DEFAULT_HIVE: u32 = 0x1000_0000;
const DEFAULT_MOUNT: &str = r"\Registry\User\.Default";
/// `registry_target_path(MACHINE_ROOT_KEY)`.
const MACHINE_ROOT: &str = r"\registry\machine";

const WATCHER: u64 = 0x2C;
const THREAD: u64 = 0x31C;

fn registry() -> MutableHiveSet {
    let mut software = Hive::new(HiveKind::Software);
    software.create_key(r"Microsoft\CTF\TIP");
    software.create_key(r"Microsoft\Speech");
    software.create_key(r"Microsoft\Windows\CurrentVersion\Run");
    let mut default = Hive::new(HiveKind::Default);
    default.create_key(r"Software\Microsoft\Windows\CurrentVersion\Run");
    default.create_key(r"Software\Microsoft\Speech");
    default.create_key(r"Software\Wine\Drivers\winealsa.drv");
    let mut set = MutableHiveSet::new();
    set.mount(SOFTWARE_MOUNT, SOFTWARE_HIVE, software).unwrap();
    set.mount(DEFAULT_MOUNT, DEFAULT_HIVE, default).unwrap();
    set
}

/// The key a handle opened by `path` names, as the executive resolves an open.
fn opened(set: &MutableHiveSet, path: &str) -> ResolvedHiveKey {
    set.resolve_key(path)
        .unwrap_or_else(|| panic!("{path} resolves"))
}

/// `registry_target_path` of a mutable-hive handle (`mutable_key_path`).
fn handle_name(set: &MutableHiveSet, key: ResolvedHiveKey) -> String {
    set.key_name(key).expect("a mounted key has a name")
}

fn arm(notifier: &mut ChangeNotifier<u32>, handle: u64, name: &str, filter: u32, tree: bool) {
    let body = KeyBody {
        process: WATCHER,
        handle,
    };
    let armed = notifier
        .arm(body, name, filter, tree, THREAD, handle as u32)
        .unwrap();
    assert!(matches!(armed, Armed::Pending(_)), "{name}: armed pending");
}

fn completed(completions: &[Completion<u32>]) -> Vec<(u32, u32)> {
    completions
        .iter()
        .map(|done| (done.request, done.status))
        .collect()
}

#[test]
fn ctfmon_run_watch_on_hkcu_completes_when_a_value_of_that_key_changes() {
    let set = registry();
    let mut notifier = ChangeNotifier::new();
    // HKCU (no per-user hive loaded) is `\Registry\User\.Default`; ctfmon opens `Run` below it.
    let run = opened(
        &set,
        r"\Registry\User\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run",
    );
    arm(
        &mut notifier,
        0x40,
        &handle_name(&set, run),
        REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
        false,
    );

    // RegDeleteValue(Run, "internat.exe") through another handle: `journal_delete_mutable_value`.
    let writer = opened(
        &set,
        r"\REGISTRY\USER\.default\software\microsoft\windows\currentversion\run",
    );
    let done = notifier.report_key_changed(&handle_name(&set, writer), REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(completed(&done), [(0x40, STATUS_NOTIFY_ENUM_DIR)]);
}

#[test]
fn mmdevapi_driver_watch_completes_on_a_value_set() {
    let set = registry();
    let mut notifier = ChangeNotifier::new();
    let drivers = opened(
        &set,
        r"\Registry\User\.Default\Software\Wine\Drivers\winealsa.drv",
    );
    arm(
        &mut notifier,
        0x44,
        &handle_name(&set, drivers),
        REG_NOTIFY_CHANGE_LAST_SET,
        false,
    );
    let done = notifier.report_key_changed(&handle_name(&set, drivers), REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(completed(&done), [(0x44, STATUS_NOTIFY_ENUM_DIR)]);
}

#[test]
fn tree_watch_on_a_software_key_completes_when_a_subkey_is_created_below_it() {
    let mut set = registry();
    let mut notifier = ChangeNotifier::new();
    let tip = opened(&set, r"\Registry\Machine\SOFTWARE\Microsoft\CTF\TIP");
    arm(
        &mut notifier,
        0x48,
        &handle_name(&set, tip),
        REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
        true,
    );

    // NtCreateKey: `journal_create_secured_mutable_subkey` reports the child it created.
    let child = set
        .create_key(r"\registry\machine\software\Microsoft\CTF\TIP\{Profile}\LanguageProfile")
        .unwrap();
    let done = notifier.report_subkey_changed(&handle_name(&set, child));
    assert_eq!(completed(&done), [(0x48, STATUS_NOTIFY_ENUM_DIR)]);
}

#[test]
fn hklm_tree_watch_sees_a_change_inside_the_mounted_software_hive() {
    let set = registry();
    let mut notifier = ChangeNotifier::new();
    arm(
        &mut notifier,
        0x4C,
        MACHINE_ROOT,
        REG_NOTIFY_CHANGE_LAST_SET,
        true,
    );
    let speech = opened(&set, r"\Registry\Machine\Software\Microsoft\Speech");
    let done = notifier.report_key_changed(&handle_name(&set, speech), REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(completed(&done), [(0x4C, STATUS_NOTIFY_ENUM_DIR)]);
}

#[test]
fn a_base_hive_handle_and_a_mutable_handle_name_the_same_key() {
    let set = registry();
    let mut notifier = ChangeNotifier::new();
    // A read-only REGF handle: `registry_target_path` joins the mount path and the cell's
    // hive-relative path (original case, no leading separator) and canonicalizes the result.
    let base = set.canonical_name(&format!(
        r"{SOFTWARE_MOUNT}\{}",
        r"Microsoft\Windows\CurrentVersion\Run"
    ));
    arm(
        &mut notifier,
        0x50,
        &base,
        REG_NOTIFY_CHANGE_LAST_SET,
        false,
    );
    let run = opened(
        &set,
        r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    );
    assert_eq!(base, handle_name(&set, run));
    let done = notifier.report_key_changed(&handle_name(&set, run), REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(completed(&done), [(0x50, STATUS_NOTIFY_ENUM_DIR)]);
}

#[test]
fn hkcu_and_hklm_keys_with_the_same_relative_path_are_different_keys() {
    let set = registry();
    let mut notifier = ChangeNotifier::new();
    let user = opened(&set, r"\Registry\User\.Default\Software\Microsoft\Speech");
    let machine = opened(&set, r"\Registry\Machine\SOFTWARE\Microsoft\Speech");
    arm(
        &mut notifier,
        0x54,
        &handle_name(&set, user),
        REG_NOTIFY_CHANGE_LAST_SET,
        true,
    );
    arm(
        &mut notifier,
        0x58,
        &handle_name(&set, machine),
        REG_NOTIFY_CHANGE_LAST_SET,
        true,
    );
    let done = notifier.report_key_changed(&handle_name(&set, machine), REG_NOTIFY_CHANGE_LAST_SET);
    assert_eq!(completed(&done), [(0x58, STATUS_NOTIFY_ENUM_DIR)]);
    assert_eq!(notifier.posted_requests(), 1);
}
