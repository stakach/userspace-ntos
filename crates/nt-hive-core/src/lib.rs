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
mod hive;
mod io;
mod overlay;

pub use overlay::{canon_path, RegistryOverlay};

pub use codec::{
    decode_image, encode_image, encode_log_record, replay_log, HiveDecodeError, HiveLogOp,
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
