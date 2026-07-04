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
use nt_setupapi as setupapi;
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

    // --- User-mode device discovery (CfgMgr32 + SetupAPI) --------------------
    // A user program enumerates the {9A7B…} interface + resolves its device path (spec §14).
    let lc_guid = "{9a7b0b24-6e57-4c51-ad3c-6d9f5f0e0001}";
    let size = setupapi::cm_get_device_interface_list_size(
        &cm,
        Some(lc_guid),
        None,
        setupapi::CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    );
    let list = size.and_then(|n| {
        setupapi::cm_get_device_interface_list(&cm, Some(lc_guid), None, n, setupapi::CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
    });
    let cm_path = list.as_ref().ok().map(|l| decode_first_multi_sz(l)).unwrap_or_default();
    check(
        b"cfgmgr32_lists_interface_path",
        list.ok().map(|l| l.len() as u32) == size.ok() && cm_path.starts_with(r"\\?\"),
    );

    // Edge cases (§9.4): null GUID + unknown flags rejected.
    check(
        b"cfgmgr32_edge_cases",
        setupapi::cm_get_device_interface_list_size(&cm, None, None, 0)
            == Err(setupapi::ConfigRet::InvalidPointer)
            && setupapi::cm_get_device_interface_list_size(&cm, Some(lc_guid), None, 0x8000)
                == Err(setupapi::ConfigRet::InvalidFlag),
    );

    // SetupAPI: HDEVINFO → enumerate → two-call detail → destroy (spec §11).
    let mut sets = setupapi::DevInfoSets::new();
    let h = sets.get_class_devs(&cm, Some(lc_guid), setupapi::DIGCF_PRESENT | setupapi::DIGCF_DEVICEINTERFACE);
    let elem = sets.enum_device_interfaces(h, 0);
    let (need_err, required) = sets.get_device_interface_detail(h, 0, 0).unwrap_err();
    let sp_path = sets
        .get_device_interface_detail(h, 0, required)
        .ok()
        .map(|p| decode_wstr(&p))
        .unwrap_or_default();
    let destroyed = sets.destroy_device_info_list(h);
    check(
        b"setupapi_enumerate_and_detail",
        h.is_valid()
            && elem.is_some()
            && need_err == setupapi::ERROR_INSUFFICIENT_BUFFER
            && sp_path == cm_path
            && destroyed
            && sets.enum_device_interfaces(h, 0).is_none(), // stale after destroy
    );

    // --- Hive Manager: SYSTEM hive survives a reboot (spec §16, §18) ---------
    use nt_hive_core::{HiveKind, HiveLogOp, HiveManager, HiveMountTable, MemoryHiveIoProvider, RegistryValueType as HRegType};
    // Mount table resolves CurrentControlSet through the SYSTEM hive (spec §8).
    let mut mounts = HiveMountTable::new();
    mounts.mount(nt_hive_core::SYSTEM_HIVE_PATH, 1);
    let resolved = mounts.resolve(r"\Registry\Machine\System\CurrentControlSet\Services\Foo");
    check(
        b"hive_mount_resolves_currentcontrolset",
        resolved.as_ref().map(|(h, r)| (*h, r.as_str()))
            == Some((1, r"\ControlSet001\Services\Foo")),
    );

    let mut mgr = HiveManager::new(MemoryHiveIoProvider::new());
    let mut hive = mgr.boot(HiveKind::System).unwrap(); // fresh (no image yet)
    let svc = r"ControlSet001\Services\KmdfInterfaceRegistryTest\Parameters";
    mgr.mutate(&mut hive, HiveLogOp::CreateKey { path: svc }).ok();
    mgr.mutate(&mut hive, HiveLogOp::SetValue { path: svc, name: "Answer", value_type: HRegType::Dword, data: &42u32.to_le_bytes() }).ok();
    mgr.flush(&mut hive).ok(); // checkpoint into the image, truncate log
    // A driver write after the checkpoint (journaled to the log only).
    mgr.mutate(&mut hive, HiveLogOp::SetValue { path: svc, name: "SeenByDriver", value_type: HRegType::Dword, data: &1u32.to_le_bytes() }).ok();

    // Reboot: a fresh HiveManager over the same provider (image + replayed log).
    let provider = mgr.into_provider();
    let booted = HiveManager::new(provider).boot(HiveKind::System);
    let hive_ok = booted
        .map(|hv| {
            let key = hv.open_key(svc).unwrap();
            hv.query_dword(key, "Answer") == Some(42) // from the image
                && hv.query_dword(key, "SeenByDriver") == Some(1) // from the replayed log
        })
        .unwrap_or(false);
    check(b"hive_boot_survives_restart", hive_ok);

    // --- Filesystem runtime: MemFs + Zw* file APIs + hive-on-disk (spec §8, §14) ----
    use core::cell::RefCell;
    use nt_fs::{FileSystem, MemFs, NtFileHiveIoProvider};
    // A MemFs volume with the fixture tree; ZwCreateFile a temp file, write + read it back.
    let fs = RefCell::new(FileSystem::new(MemFs::with_fixture()));
    let file_ok = {
        let mut f = fs.borrow_mut();
        let c = f.zw_create_file(r"\??\C:\Temp\probe", nt_fs::FILE_WRITE_DATA, 0, 0, nt_fs::FILE_CREATE, 0);
        let wrote = f.zw_write_file(c.handle, None, b"hello fs").1;
        let size = f.zw_query_standard_information(c.handle).map(|i| i.end_of_file).unwrap_or(0);
        f.zw_close(c.handle);
        let r = f.zw_create_file(r"\??\C:\Temp\probe", nt_fs::FILE_READ_DATA, 0, 0, nt_fs::FILE_OPEN, 0);
        let (st, bytes) = f.zw_read_file(r.handle, Some(0), 8);
        f.zw_close(r.handle);
        c.status == nt_fs::STATUS_SUCCESS
            && c.information == nt_fs::FILE_CREATED
            && wrote == 8
            && size == 8
            && st == nt_fs::STATUS_SUCCESS
            && &bytes[..] == b"hello fs"
    };
    check(b"memfs_zw_create_read_write", file_ok);

    // §14.2 acceptance: a hive image persists through the Zw* file APIs on MemFs across a restart.
    let sys_hive = r"\SystemRoot\System32\Config\SYSTEM";
    {
        let mut mgr = HiveManager::new(NtFileHiveIoProvider::open(&fs, sys_hive));
        let mut hv = mgr.boot(HiveKind::System).unwrap();
        mgr.mutate(&mut hv, HiveLogOp::CreateKey { path: svc }).ok();
        mgr.mutate(&mut hv, HiveLogOp::SetValue { path: svc, name: "Answer", value_type: HRegType::Dword, data: &42u32.to_le_bytes() }).ok();
        mgr.flush(&mut hv).ok(); // image file written under \Windows\System32\Config\SYSTEM
        mgr.mutate(&mut hv, HiveLogOp::SetValue { path: svc, name: "SeenByDriver", value_type: HRegType::Dword, data: &1u32.to_le_bytes() }).ok();
    }
    let disk_ok = HiveManager::new(NtFileHiveIoProvider::open(&fs, sys_hive))
        .boot(HiveKind::System)
        .map(|hv| {
            let key = hv.open_key(svc).unwrap();
            hv.query_dword(key, "Answer") == Some(42) // from the image file
                && hv.query_dword(key, "SeenByDriver") == Some(1) // from the replayed log file
        })
        .unwrap_or(false);
    check(b"hive_persists_through_memfs_file", disk_ok);

    // --- Cache Manager: cached I/O over a MemFs file (spec §12-14, §22) -------
    use nt_cache_manager::{FileSizes, SharedCacheMap};
    use nt_fs::FileBacking;
    {
        let mut f = fs.borrow_mut();
        f.zw_create_file(r"\??\C:\Temp\cached.bin", nt_fs::FILE_WRITE_DATA, 0, 0, nt_fs::FILE_CREATE, 0);
    }
    // Write through the cache; the dirty page holds the data until flush.
    let empty = FileSizes { allocation_size: 0, file_size: 0, valid_data_length: 0 };
    let cache_ok = {
        let mut ccm = SharedCacheMap::cc_initialize_cache_map(FileBacking::open(&fs, r"\??\C:\Temp\cached.bin"), empty, false);
        ccm.cc_copy_write(0, b"cached through memfs", false);
        let dirty_before = ccm.cc_is_there_dirty_data();
        // A cached read is served from the dirty page (no backing round-trip needed).
        let mut rb = [0u8; 20];
        let (_, rn) = ccm.cc_copy_read(0, 20, &mut rb);
        ccm.cc_flush_cache(None, None); // write dirty pages back to the MemFs file
        dirty_before && !ccm.cc_is_there_dirty_data() && rn == 20 && &rb[..] == b"cached through memfs"
    };
    check(b"cachemgr_write_read_flush", cache_ok);
    // The flushed bytes are now in the MemFs file; a fresh cache map faults them back in.
    let reload_ok = {
        let full = FileSizes { allocation_size: 20, file_size: 20, valid_data_length: 20 };
        let mut ccm = SharedCacheMap::cc_initialize_cache_map(FileBacking::open(&fs, r"\??\C:\Temp\cached.bin"), full, false);
        let mut rb = [0u8; 20];
        let (_, rn) = ccm.cc_copy_read(0, 20, &mut rb);
        rn == 20 && &rb[..] == b"cached through memfs"
    };
    check(b"cachemgr_reload_from_backing", reload_ok);

    // --- Memory Manager: mapped section of a MemFs file (spec §24 acceptance) ----
    use nt_memory_manager::{AddressSpace, MemoryManager};
    // 1-3. Create + write the file "abcdef".
    let mapped = r"\??\C:\Temp\mapped.bin";
    {
        let mut f = fs.borrow_mut();
        let c = f.zw_create_file(mapped, nt_fs::FILE_WRITE_DATA, 0, 0, nt_fs::FILE_CREATE, 0);
        f.zw_write_file(c.handle, Some(0), b"abcdef");
        f.zw_close(c.handle);
    }
    let mm_ok = {
        // 4. Section over the file, coherent through a cache map.
        let mut cache = SharedCacheMap::cc_initialize_cache_map(
            FileBacking::open(&fs, mapped),
            FileSizes { allocation_size: 6, file_size: 6, valid_data_length: 6 },
            false,
        );
        let mut mm = MemoryManager::new();
        let sec = mm
            .zw_create_section_file(6, nt_memory_manager::PAGE_READWRITE, nt_memory_manager::SEC_COMMIT)
            .unwrap();
        // 5-7. Map, verify "abcdef", edit "XYZ" at offset 1.
        let view = mm
            .zw_map_view_of_section_file(sec, &mut cache, 0, 0, nt_memory_manager::PAGE_READWRITE, AddressSpace::Process)
            .unwrap();
        let seen = mm.view_read(view, 0, 6).unwrap();
        mm.view_write(view, 1, b"XYZ").unwrap();
        // 8-9. Unmap (writeback → cache dirty) + flush to the file.
        mm.zw_unmap_view_of_section_file(view, &mut cache).unwrap();
        cache.cc_flush_cache(None, None);
        seen == b"abcdef"
    };
    // 10. ZwReadFile returns the edited "aXYZef".
    let final_bytes = {
        let mut f = fs.borrow_mut();
        let r = f.zw_create_file(mapped, nt_fs::FILE_READ_DATA, 0, 0, nt_fs::FILE_OPEN, 0);
        let (_, b) = f.zw_read_file(r.handle, Some(0), 6);
        f.zw_close(r.handle);
        b
    };
    check(b"memmgr_mapped_file_edit", mm_ok && &final_bytes[..] == b"aXYZef");

    // Anonymous (pagefile) section shared across views.
    let anon_ok = {
        let mut mm = MemoryManager::new();
        let sec = mm.zw_create_section_pagefile(16, nt_memory_manager::PAGE_READWRITE, nt_memory_manager::SEC_COMMIT).unwrap();
        let v1 = mm.zw_map_view_of_section_anon(sec, 0, 16, nt_memory_manager::PAGE_READWRITE, AddressSpace::Process).unwrap();
        mm.view_write(v1, 4, b"anon").unwrap();
        mm.zw_unmap_view_of_section_anon(v1).unwrap();
        let v2 = mm.zw_map_view_of_section_anon(sec, 0, 16, nt_memory_manager::PAGE_READONLY, AddressSpace::Process).unwrap();
        mm.view_read(v2, 4, 4).unwrap() == b"anon"
    };
    check(b"memmgr_anonymous_section", anon_ok);

    // --- Address space: demand-paged mapped MemFs file (spec §12 fault path) ----
    use nt_address_space::{AddressSpace as VaSpace, FaultAccess, ViewType};
    // Re-seed the mapped file to "abcdef" (M24 left it "aXYZef").
    {
        let mut f = fs.borrow_mut();
        let c = f.zw_create_file(mapped, nt_fs::FILE_WRITE_DATA, 0, 0, nt_fs::FILE_OVERWRITE_IF, 0);
        f.zw_write_file(c.handle, Some(0), b"abcdef");
        f.zw_close(c.handle);
    }
    let mut fcache = SharedCacheMap::cc_initialize_cache_map(
        FileBacking::open(&fs, mapped),
        FileSizes { allocation_size: 6, file_size: 6, valid_data_length: 6 },
        false,
    );
    let mut aspace = VaSpace::new(0x1_0000, 0x1000_0000, 0x1000_0000);
    let (vad, base) = aspace
        .reserve_view(None, 6, nt_address_space::PAGE_READWRITE, ViewType::MappedDataSection, Some(1), 0)
        .unwrap();
    // Demand paging: nothing resident until a fault touches it.
    let not_resident = aspace.resident_page_count() == 0;
    let read_ok = aspace.read(base, 6, &mut fcache).map(|b| &b[..] == b"abcdef").unwrap_or(false);
    let resident_after = aspace.resident_page_count() == 1;
    check(b"addrspace_demand_fault", not_resident && read_ok && resident_after);
    // Access violation on an unreserved VA (fault with no VAD).
    let av = aspace.fault(0x5000_0000, FaultAccess::Read, &mut fcache) == nt_address_space::STATUS_ACCESS_VIOLATION;
    check(b"addrspace_access_violation", av);
    // Edit through the fault/write path → unmap writeback → flush → the file reflects it.
    aspace.write(base + 1, b"XYZ", &mut fcache).unwrap();
    aspace.unmap_view(vad, &mut fcache).unwrap();
    fcache.cc_flush_cache(None, None);
    let edited = {
        let mut f = fs.borrow_mut();
        let r = f.zw_create_file(mapped, nt_fs::FILE_READ_DATA, 0, 0, nt_fs::FILE_OPEN, 0);
        let (_, b) = f.zw_read_file(r.handle, Some(0), 6);
        f.zw_close(r.handle);
        b
    };
    check(b"addrspace_writeback_to_file", &edited[..] == b"aXYZef" && aspace.commit_charge() == 0);

    // --- Process Manager: process/thread lifecycle + handle tables (spec §7-§12) ----
    use nt_process::{ClientId, HandleObject, ProcessManager, ProcessState, ThreadState};
    let mut pm = ProcessManager::new();
    let p1 = pm.create_process("worker.exe", None, None);
    // First thread makes the process Running + becomes the main thread.
    let t1 = pm.create_thread(p1, 0x1_4000_1000, 0, false).unwrap();
    pm.set_thread_state(t1, ThreadState::Running).unwrap();
    let lifecycle_ok = pm.process(p1).unwrap().state == ProcessState::Running
        && pm.process(p1).unwrap().main_thread == Some(t1)
        && pm.client_id(t1) == Some(ClientId { unique_process: p1, unique_thread: t1 });
    check(b"process_thread_lifecycle", lifecycle_ok);

    // Handle table: insert a cross-process handle, duplicate it, close it (process-local).
    let p2 = pm.create_process("helper.exe", None, None);
    let h = pm.insert_handle(p1, HandleObject::Process(p2), 0x1F_0000).unwrap();
    // Handles are process-local: h isn't valid in p2's (still empty) table.
    let local_ok = pm.lookup_handle(p1, h) == Some(HandleObject::Process(p2))
        && pm.lookup_handle(p2, h).is_none();
    let hdup = pm.duplicate_handle(p1, h, p2).unwrap();
    let handles_ok = local_ok
        && pm.lookup_handle(p2, hdup) == Some(HandleObject::Process(p2))
        && pm.close_handle(p1, h).is_ok()
        && pm.lookup_handle(p1, h).is_none();
    check(b"process_handle_table", handles_ok);

    // Termination signals the process object; a system thread doesn't force process exit.
    let sys = pm.create_thread(p1, 0x1_4000_2000, 0, true).unwrap();
    pm.terminate_thread(t1, 7).unwrap(); // last non-system thread → process exits
    let term_ok = pm.is_thread_signaled(t1)
        && pm.is_process_signaled(p1)
        && pm.wait_process(p1) == Some(7)
        && pm.is_thread_signaled(sys) // terminated by process exit
        && !pm.is_process_signaled(p2); // unrelated process unaffected
    check(b"process_terminate_signal", term_ok);

    // --- Security Reference Monitor: tokens + access check (spec §7-§9) -------
    use nt_security::{
        access_check, Ace, Acl, GenericMapping, ProcessorMode, SecurityDescriptor, Sid, AccessToken,
        ACCESS_SYSTEM_SECURITY, READ_CONTROL, SYNCHRONIZE, WRITE_OWNER, SE_SECURITY, SE_TAKE_OWNERSHIP,
    };
    const FILE_READ: u32 = 0x1;
    const FILE_WRITE: u32 = 0x2;
    const MACHINE: u32 = 0x1234;
    let map = GenericMapping {
        generic_read: FILE_READ | READ_CONTROL | SYNCHRONIZE,
        generic_write: FILE_WRITE | READ_CONTROL | SYNCHRONIZE,
        generic_execute: READ_CONTROL | SYNCHRONIZE,
        generic_all: FILE_READ | FILE_WRITE | READ_CONTROL | WRITE_OWNER,
    };
    // SIDs + SDDL string form.
    check(b"security_wellknown_sids", Sid::administrators().to_sddl() == "S-1-5-32-544");

    // DACL: deny Users write, then allow Everyone read+write (canonical order).
    let sd = SecurityDescriptor {
        owner: Some(Sid::local_account(MACHINE, 1000)),
        dacl: Some(Acl::new(alloc::vec![
            Ace::deny(Sid::users(), FILE_WRITE),
            Ace::allow(Sid::everyone(), FILE_READ | FILE_WRITE),
        ])),
        ..Default::default()
    };
    let admin = AccessToken::admin(MACHINE);
    let user = AccessToken::user(MACHINE);
    // Admin (not in the deny-Users? admin IS in Users too) — check the user path: read granted, write denied.
    let user_read = access_check(&sd, &user, FILE_READ, &map, ProcessorMode::UserMode).granted();
    let user_write = access_check(&sd, &user, FILE_WRITE, &map, ProcessorMode::UserMode).granted();
    check(b"security_deny_before_allow", user_read && !user_write);

    // Owner gets READ_CONTROL even against an empty DACL; KernelMode bypasses the DACL.
    let empty = SecurityDescriptor { owner: Some(user.user.clone()), dacl: Some(Acl::empty()), ..Default::default() };
    let owner_rc = access_check(&empty, &user, READ_CONTROL, &map, ProcessorMode::UserMode).granted();
    let kernel_bypass = access_check(&empty, &user, FILE_READ | FILE_WRITE, &map, ProcessorMode::KernelMode).granted();
    check(b"security_owner_and_kernel", owner_rc && kernel_bypass);

    // Privilege overrides: ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege (System has it, user
    // doesn't); WRITE_OWNER via SeTakeOwnershipPrivilege (admin) against an empty DACL.
    let sys_sec = access_check(&empty, &AccessToken::system(), ACCESS_SYSTEM_SECURITY, &map, ProcessorMode::UserMode);
    let user_sec_denied = !access_check(&empty, &user, ACCESS_SYSTEM_SECURITY, &map, ProcessorMode::UserMode).granted();
    let admin_wo = access_check(&empty, &admin, WRITE_OWNER, &map, ProcessorMode::UserMode);
    check(
        b"security_privilege_overrides",
        sys_sec.granted() && sys_sec.privileges_used.contains(&SE_SECURITY)
            && user_sec_denied
            && admin_wo.granted() && admin_wo.privileges_used.contains(&SE_TAKE_OWNERSHIP),
    );
}

/// Decode the first NUL-terminated string of a `MULTI_SZ` (UTF-16LE code units).
fn decode_first_multi_sz(list: &[u16]) -> alloc::string::String {
    let units: alloc::vec::Vec<u16> = list.iter().copied().take_while(|&u| u != 0).collect();
    char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect()
}
/// Decode a NUL-terminated UTF-16LE string.
fn decode_wstr(s: &[u16]) -> alloc::string::String {
    let units: alloc::vec::Vec<u16> = s.iter().copied().take_while(|&u| u != 0).collect();
    char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect()
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
