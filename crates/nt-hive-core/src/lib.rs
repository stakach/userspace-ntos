//! # `nt-hive-core` — NT registry hive model + Hive I/O Provider
//!
//! The registry expressed as NT **hives** (spec: NT Hive Manager + Configuration Manager Hive
//! I/O Provider): a [`Hive`] is a cell arena of [`hive::KeyCell`]s + [`hive::ValueCell`]s
//! addressed by a stable [`CellId`] (never a raw pointer). A [`HiveMountTable`] resolves a full
//! NT registry path to a mounted hive + a relative path, applying the `CurrentControlSet` alias.
//! Hives persist through a versioned, checksummed **image** + an append-only **log** (replayed
//! on boot) behind a pluggable [`HiveIoProvider`] (Memory / FaultInjection / future NtFile), with
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
    seed_reactos_explorer_shell_com_classes, utf16le_sz, ReactOsComClassRegistrationScript,
    CLSID_REBAR_BAND_SITE, CLSID_START_MENU, REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE,
    REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU,
    REACTOS_EXPLORER_SHELL_COM_REGISTRATION_SCRIPTS,
};

pub use codec::{
    decode_image, encode_image, encode_log_record, replay_log, HiveDecodeError, HiveLogOp,
};
pub use config_import::{
    import_control_set_class_into_config_manager, import_control_set_enum_into_config_manager,
    import_control_set_services_into_config_manager,
};
pub use hive::{
    apply_ccs_alias, CellId, Hive, HiveId, HiveKind, HiveMountTable, RegistryValueType,
    CURRENT_CONTROL_SET_TARGET, SYSTEM_HIVE_PATH,
};
pub use io::{
    FaultInjectionHiveIoProvider, FlushMode, HiveIoError, HiveIoProvider, HiveIoProviderKind,
    HiveIoStatus, HiveManager, MemoryHiveIoProvider, NtFileHiveIoProvider,
};

#[cfg(test)]
mod tests;
