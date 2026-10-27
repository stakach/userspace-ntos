//! Released LiberNT drivers resolve the same live EX rundown ABI as win32k.

#[cfg(target_arch = "x86_64")]
use nt_kernel_exec::ExRundownRef;
#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

#[cfg(target_arch = "x86_64")]
#[path = "../../../components/ntos-executive/src/ex_rundown_exports.rs"]
mod ex_rundown_exports;

#[cfg(target_arch = "x86_64")]
fn yield_now() {
    std::thread::yield_now();
}

const RUNDOWN_IMPORTS: [&str; 5] = [
    "ExAcquireRundownProtection",
    "ExInitializeRundownProtection",
    "ExReInitializeRundownProtection",
    "ExReleaseRundownProtection",
    "ExWaitForRundownProtectionRelease",
];

#[test]
fn pinned_drivers_resolve_rundown_through_generic_export_registry() {
    for driver in ["acpi.sys", "basicdisplay.sys"] {
        let imported = libernt_driver_imports::imports(driver, &["ntoskrnl.exe"]);
        assert!(imported.contains("ExAcquireRundownProtection"), "{driver} must exercise the pinned import frontier");
    }

    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("crate::ex_rundown_exports::bind_ex_rundown_exports(reg);"));
    let source = include_str!("../../../components/ntos-executive/src/ex_rundown_exports.rs");
    assert!(source.matches("extern \"win64\" fn ex_").count() >= 5, "the basic direct exports must use the native Win64 ABI");
    for name in RUNDOWN_IMPORTS {
        assert!(source.contains(&format!("reg.bind(\"{name}\",")), "generic driver registry lacks {name}");
    }
}

const CLASS_PNP_CACHE_AWARE_IMPORTS: [&str; 6] = [
    "ExAcquireRundownProtectionCacheAware",
    "ExInitializeRundownProtectionCacheAware",
    "ExReInitializeRundownProtectionCacheAware",
    "ExReleaseRundownProtectionCacheAware",
    "ExSizeOfRundownProtectionCacheAware",
    "ExWaitForRundownProtectionReleaseCacheAware",
];

#[test]
fn pinned_classpnp_cache_aware_rundown_imports_have_real_native_bindings() {
    use nt_pe_loader::ImportRef;
    use std::collections::BTreeSet;
    use std::path::Path;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/classpnp.sys");
    if image.exists() {
        let bytes = std::fs::read(image).expect("staged pinned classpnp.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("classpnp PE");
        let imports: BTreeSet<String> = pe.imports().expect("classpnp imports")
            .into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .filter_map(|entry| match entry {
                ImportRef::ByName { name, .. } => Some(name),
                ImportRef::ByOrdinal { .. } => None,
            })
            .collect();
        for name in CLASS_PNP_CACHE_AWARE_IMPORTS {
            assert!(imports.contains(name), "pinned classpnp.sys no longer imports {name}");
        }
    }

    // The generic driver resolver enters this registry before DriverEntry. A source check runs
    // on CI hosts without the staged image and stays red until each real direct export is bound.
    let resolver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(resolver.contains("crate::ex_rundown_exports::bind_ex_rundown_exports(reg);"));
    let exports = include_str!("../../../components/ntos-executive/src/ex_rundown_exports.rs");
    for name in CLASS_PNP_CACHE_AWARE_IMPORTS {
        assert!(exports.contains(&format!("reg.bind(\"{name}\","))
            || exports.contains(&format!("reg.bind(\n        \"{name}\",")),
            "classpnp.sys cannot load: missing live cache-aware rundown export {name}");
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn shared_win64_exports_preserve_real_descriptor_lifecycle() {
    let initialize: extern "win64" fn(*const ExRundownRef) =
        ex_rundown_exports::ex_initialize_rundown_protection;
    let acquire: extern "win64" fn(*const ExRundownRef) -> u8 =
        ex_rundown_exports::ex_acquire_rundown_protection;
    let release: extern "win64" fn(*const ExRundownRef) =
        ex_rundown_exports::ex_release_rundown_protection;
    let wait: extern "win64" fn(*const ExRundownRef) =
        ex_rundown_exports::ex_wait_for_rundown_protection_release;
    let reinitialize: extern "win64" fn(*const ExRundownRef) =
        ex_rundown_exports::ex_reinitialize_rundown_protection;

    let reference = Box::new(ExRundownRef::new());
    let ptr = &*reference as *const ExRundownRef;
    initialize(ptr);
    assert_eq!(acquire(ptr), 1);
    assert_eq!(acquire(ptr), 1);

    std::thread::scope(|scope| {
        let waiter_ptr = ptr as usize;
        let waiter = scope.spawn(move || wait(waiter_ptr as *const ExRundownRef));
        release(ptr);
        release(ptr);
        waiter.join().expect("rundown waiter must drain both references");
    });
    assert_eq!(acquire(ptr), 0, "completed rundown closes admission");
    reinitialize(ptr);
    assert_eq!(acquire(ptr), 1, "reinitialize reopens admission");
    release(ptr);
}
