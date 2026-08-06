//! Import hive subtrees into the live Configuration Manager registry.

use alloc::vec::Vec;

use nt_config_manager::{
    ConfigManager, Registry, RegistryKeyId, CONTROL_CLASS_PATH, ENUM_PATH, SERVICES_PATH,
};

use crate::Hive;

/// Import `ControlSetXXX\Services` from a hive into
/// `\Registry\Machine\System\CurrentControlSet\Services`.
///
/// This keeps the Configuration Manager registry as the typed service metadata authority while
/// still allowing early boot to source a hive image first.
pub fn import_control_set_services_into_config_manager(
    hive: &Hive,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_services_path = alloc::string::String::from(control_set);
    src_services_path.push_str("\\Services");
    let Some(src_services) = hive.open_key(&src_services_path) else {
        return 0;
    };
    let dst_services = cm.registry_mut().create_key(SERVICES_PATH);
    let service_names = hive.enum_subkeys(src_services);
    let count = service_names.len();
    for name in service_names {
        let Some(src_service) = hive.open_subkey(src_services, &name) else {
            continue;
        };
        let dst_service = cm.registry_mut().create_subkey(dst_services, &name);
        import_hive_key(hive, src_service, cm.registry_mut(), dst_service);
    }
    count
}

/// Import `ControlSetXXX\Enum` from a hive into
/// `\Registry\Machine\System\CurrentControlSet\Enum`, then index devnode records from the imported
/// registry keys.
pub fn import_control_set_enum_into_config_manager(
    hive: &Hive,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_enum_path = alloc::string::String::from(control_set);
    src_enum_path.push_str("\\Enum");
    let Some(src_enum) = hive.open_key(&src_enum_path) else {
        return 0;
    };
    let dst_enum = cm.registry_mut().create_key(ENUM_PATH);
    import_hive_key(hive, src_enum, cm.registry_mut(), dst_enum);
    cm.index_registry_devnodes()
}

/// Import `ControlSetXXX\Control\Class` from a hive into
/// `\Registry\Machine\System\CurrentControlSet\Control\Class`.
pub fn import_control_set_class_into_config_manager(
    hive: &Hive,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_class_path = alloc::string::String::from(control_set);
    src_class_path.push_str("\\Control\\Class");
    let Some(src_class) = hive.open_key(&src_class_path) else {
        return 0;
    };
    let dst_class = cm.registry_mut().create_key(CONTROL_CLASS_PATH);
    let class_names = hive.enum_subkeys(src_class);
    let count = class_names.len();
    for name in class_names {
        let Some(src_child) = hive.open_subkey(src_class, &name) else {
            continue;
        };
        let dst_child = cm.registry_mut().create_subkey(dst_class, &name);
        import_hive_key(hive, src_child, cm.registry_mut(), dst_child);
    }
    count
}

fn import_hive_key(hive: &Hive, src: crate::CellId, dst: &mut Registry, dst_key: RegistryKeyId) {
    for value_name in hive.enum_values(src) {
        if let Some((value_type, data)) = hive.query_value(src, &value_name) {
            let _ = dst.set_value(dst_key, &value_name, value_type, Vec::from(data));
        }
    }
    for child_name in hive.enum_subkeys(src) {
        let Some(src_child) = hive.open_subkey(src, &child_name) else {
            continue;
        };
        let dst_child = dst.create_subkey(dst_key, &child_name);
        import_hive_key(hive, src_child, dst, dst_child);
    }
}
