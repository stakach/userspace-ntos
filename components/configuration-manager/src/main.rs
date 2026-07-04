//! `ntos-configuration-manager` — the NT Configuration Manager (registry) as a seL4 component.
//!
//! Boots the registry authority bare-metal, seeds the spec §21 configuration fixture
//! (the `KmdfInterfaceRegistryTest` service + its `Parameters`, a devnode, a device
//! interface), and exercises the registry the way a driver + the PnP/interface managers
//! would: query `Answer`/`Greeting`, write `SeenByDriver`, resolve the `DriverEntry`
//! RegistryPath, enumerate the devnode by service, and enable/disable the interface. This is
//! the v0.1 in-process model (spec §5.1 / §20.1) — a later revision isolates it behind SURT.

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;

use nt_config_manager::{encode_sz, ConfigManager, RegistryValueType, DEVICE_CLASSES_PATH, SERVICES_PATH};
use nt_config_store::{journal::Mutation, snapshot, MemoryStore, Persistence};
use sel4_rt::*;

const PARAMS_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Services\KmdfInterfaceRegistryTest\Parameters";

const IFACE_GUID: &str = "{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0001}";
const CLASS_GUID: &str = "{4d36e97d-e325-11ce-bfc1-08002be10318}";

fn print_str(s: &[u8]) {
    for &b in s {
        debug_put_char(b);
    }
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

fn run() {
    let mut cm = ConfigManager::new();

    // Required root keys exist at boot (spec §8.5).
    check(
        b"root_keys_present",
        cm.registry().open_key(SERVICES_PATH).is_some()
            && cm.registry().open_key(DEVICE_CLASSES_PATH).is_some(),
    );

    // --- Load the §21 fixture -------------------------------------------------
    cm.register_service(
        "KmdfInterfaceRegistryTest",
        "KmdfInterfaceRegistryTest.sys",
        Some("System"),
        Some(CLASS_GUID),
        3, // start_type = demand
        1, // error_control = normal
    );
    cm.set_service_parameter(
        "KmdfInterfaceRegistryTest",
        "Answer",
        RegistryValueType::Dword,
        42u32.to_le_bytes().to_vec(),
    );
    cm.set_service_parameter(
        "KmdfInterfaceRegistryTest",
        "Greeting",
        RegistryValueType::Sz,
        encode_sz("hello registry"),
    );
    let dn = cm.register_devnode(
        r"ROOT\KMDF_INTERFACE_TEST\0000",
        Some("KmdfInterfaceRegistryTest"),
        Some(r"\Device\NTPNP_ROOT_0004"),
        &[r"ROOT\KMDF_INTERFACE_TEST"],
        &[r"ROOT\USERSPLACE_NTOS_INTERFACE_TEST"],
    );
    let iface = cm.register_interface(dn, IFACE_GUID, "", true);

    // --- Service registration + DriverEntry RegistryPath (spec §9) ------------
    check(
        b"service_key_path",
        cm.service_key_path("kmdfinterfaceregistrytest").as_deref()
            == Some(r"\Registry\Machine\System\CurrentControlSet\Services\KmdfInterfaceRegistryTest"),
    );

    // --- Driver reads its Parameters (spec §16, §22) --------------------------
    let params = cm.service_parameters_key("KmdfInterfaceRegistryTest").unwrap();
    check(b"query_answer_42", cm.registry().query_dword(params, "Answer") == Some(42));
    check(
        b"query_greeting",
        cm.registry().query_string(params, "greeting").as_deref() == Some("hello registry"),
    );

    // --- Driver writes SeenByDriver back (WdfRegistryAssignULong) -------------
    cm.registry_mut().set_dword(params, "SeenByDriver", 1);
    check(
        b"write_seen_by_driver",
        cm.registry().query_dword(params, "SeenByDriver") == Some(1),
    );

    // --- PnP Manager enumerates the devnode by service (spec §10.3) -----------
    let devnodes = cm.devnodes_for_service("KmdfInterfaceRegistryTest");
    check(
        b"pnp_enumerates_devnode",
        devnodes.len() == 1 && devnodes[0].instance_id == r"ROOT\KMDF_INTERFACE_TEST\0000",
    );
    let enum_key = cm.devnode(r"ROOT\KMDF_INTERFACE_TEST\0000").unwrap().enum_key;
    check(
        b"devnode_service_value",
        cm.registry().query_string(enum_key, "Service").as_deref() == Some("KmdfInterfaceRegistryTest"),
    );

    // --- Device interface enable/disable (spec §11) ---------------------------
    let link = cm.interface(iface).unwrap().symbolic_link.clone();
    check(
        b"interface_registered_enabled",
        cm.interfaces_by_guid(IFACE_GUID, true).len() == 1 && link.starts_with(r"\??\"),
    );
    cm.set_interface_state(iface, false);
    check(
        b"interface_disable_hides_it",
        cm.interfaces_by_guid(IFACE_GUID, true).is_empty()
            && cm.interfaces_by_guid(IFACE_GUID, false).len() == 1,
    );
    cm.set_interface_state(iface, true); // re-enable for the persistence round-trip

    // --- Persistence: the configuration survives a simulated restart (§18-§20) ---
    let mut persistence = Persistence::new(MemoryStore::new());
    // Graceful shutdown: write a snapshot of the whole configuration.
    check(b"persistence_snapshot_written", persistence.compact(&cm).is_ok());
    // A running driver journals a registry write (SeenByDriver=1) after the snapshot.
    let journaled = persistence
        .mutate(
            &mut cm,
            Mutation::SetValue {
                path: PARAMS_PATH,
                name: "SeenByDriver",
                value_type: RegistryValueType::Dword,
                data: &1u32.to_le_bytes(),
            },
        )
        .is_ok();
    check(b"persistence_journal_write", journaled);

    // Crash + restart: boot a fresh engine from the same store (snapshot + journal replay).
    persistence.store_mut().crash();
    let store = core::mem::take(persistence.store_mut());
    let survived = Persistence::new(store)
        .boot()
        .map(|r| {
            let params = r.service_parameters_key("KmdfInterfaceRegistryTest").unwrap();
            r.registry().query_dword(params, "Answer") == Some(42)
                && r.registry().query_string(params, "Greeting").as_deref() == Some("hello registry")
                && r.registry().query_dword(params, "SeenByDriver") == Some(1) // journaled write survived
                && r.devnodes_for_service("KmdfInterfaceRegistryTest").len() == 1
                && r.interfaces_by_guid(IFACE_GUID, true).len() == 1
        })
        .unwrap_or(false);
    check(b"persistence_survives_restart", survived);

    // A corrupted snapshot is rejected (checksum), not accepted or panicked (§9.1, §23.3).
    let mut snap = snapshot::encode(&cm, 1, 0);
    let last = snap.len() - 1;
    snap[last] ^= 0xFF;
    check(b"persistence_rejects_corruption", snapshot::parse_header(&snap).is_err());
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(_bootinfo: *const BootInfo) -> ! {
    print_str(b"[ntos-cm] NT Configuration Manager: registry authority\n");
    run();
    print_str(b"[microtest done]\n");
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sel4_rt::debug_put_char(b'!');
    loop {
        yield_now();
    }
}
