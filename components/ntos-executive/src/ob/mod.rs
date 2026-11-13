//! Object Manager state owned by the executive (target layout, issue #382).
//!
//! `namespace_table.rs` holds the compact object namespace: the entry type and the table that
//! allocates and retires its slots. `slot_retirement.rs` counts what still names a slot before
//! it may be reused. Callers still live in `exec_handler.rs` and its siblings; they move here
//! as they are ported.
//!
//! Layout rule, enforced in CI by `scripts/check_executive_layout_statics.sh`: no `static`
//! under this directory. State here is a field of an owner struct.

mod namespace_table;
mod slot_retirement;

pub(crate) use namespace_table::{ObjEntry, ObjectNamespace};
