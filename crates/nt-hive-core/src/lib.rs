//! # `nt-hive-core` — NT registry hive model + Hive I/O Provider
//!
//! The registry expressed as NT **hives** (spec: NT Hive Manager + Configuration Manager Hive
//! I/O Provider): a [`Hive`] is a cell arena of [`hive::KeyCell`]s + [`hive::ValueCell`]s
//! addressed by a stable [`CellId`] (never a raw pointer). A [`HiveMountTable`] resolves a full
//! NT registry path to a mounted hive + a relative path, applying the `CurrentControlSet` alias.
//! Hives persist through a versioned, checksummed **image** + an append-only **log** (replayed
//! on boot) behind a pluggable [`HiveIoProvider`] (Memory / FaultInjection / filesystem-backed
//! providers), with
//! a [`HiveManager`] boot / mutate / flush engine. `no_std` + `alloc`; explicit TLV wire format.

#![no_std]

extern crate alloc;

mod codec;
mod config_import;
mod hive;
mod io;
mod overlay;
mod reactos_registration;

pub use overlay::{canon_path, RegistryOverlay};
pub use reactos_registration::{
    reactos_network_ipv4_defaults_for_interface,
    seed_reactos_default_user_shell_folders_in_mutable_hives,
    seed_reactos_explorer_shell_com_classes,
    seed_reactos_explorer_shell_com_classes_in_mutable_hives,
    seed_reactos_explorer_shell_com_classes_into_target,
    seed_reactos_network_bindings_from_config_manager_into_target,
    seed_reactos_network_bindings_from_pnp_driver_bindings_into_target,
    seed_reactos_network_setup_in_config_manager, seed_reactos_network_setup_in_mutable_hives,
    seed_reactos_network_setup_into_target, seed_reactos_print_setup_in_mutable_hives,
    seed_reactos_print_setup_into_target, seed_reactos_user_profile_shell_folders_in_mutable_hives,
    seed_reactos_user_profile_shell_folders_into_target, utf16le_sz,
    ReactOsComClassRegistrationScript, ReactOsNetworkIpv4Defaults, ReactOsNetworkSetupSeedStats,
    ReactOsPrintEnvironmentRegistration, ReactOsPrintSetupSeedStats, ReactOsProfileShellFolder,
    ReactOsProfileShellFolderSeedStats, ReactOsSetupSeedTarget, CLSID_REBAR_BAND_SITE,
    CLSID_START_MENU, REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE,
    REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU,
    REACTOS_EXPLORER_SHELL_COM_REGISTRATION_SCRIPTS, REACTOS_PRINT_ENVIRONMENTS,
    REACTOS_USER_PROFILE_SHELL_FOLDERS,
};

pub use codec::{
    decode_image, encode_image, encode_log_record, encoded_image_len, image_len_if_valid,
    image_root_subkey_count_if_valid, image_value_len_if_valid, replay_log, try_encode_image,
    try_encode_subtree_image, HiveDecodeError, HiveEncodeError, HiveLogOp, HiveSubtreeEncodeError,
    HIVE_IMAGE_MAGIC,
};
pub use config_import::{
    import_control_set_class_into_config_manager, import_control_set_enum_into_config_manager,
    import_control_set_network_into_config_manager,
    import_control_set_service_group_order_into_config_manager,
    import_control_set_services_into_config_manager,
};
pub use hive::{
    apply_ccs_alias, compose_hive_overlay, CellId, DeleteKeyError, Hive, HiveId, HiveKind,
    HiveMountTable, HiveOverlayError, MutableHiveSet, RegistryValueCopyProvenance,
    RegistryValueCopyProvenanceTable, RegistryValueType, ResolvedHiveKey, ResolvedHiveValue,
    CURRENT_CONTROL_SET_TARGET, SYSTEM_HIVE_PATH,
};
pub use io::{
    FaultInjectionHiveIoProvider, FlushMode, HiveBootError, HiveFlushError, HiveIoError,
    HiveIoProvider, HiveIoProviderKind, HiveIoStatus, HiveManager, MemoryHiveIoProvider,
};

#[cfg(test)]
mod tests;
