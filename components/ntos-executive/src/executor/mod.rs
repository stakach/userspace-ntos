//! Executors: the threads that run executive code (issue #382, stage 1).
//!
//! This is the first directory of the executive's target layout. It starts with the
//! executor-local context; the pool, the yield/resume glue and the hoisted service loop are
//! ported here by later steps. There is still exactly one executor, the root TCB.
//!
//! Layout rule, enforced in CI by `scripts/check_executive_layout_statics.sh`: the only
//! `static` permitted under the target-layout directories is the executor-local block in
//! `local.rs`. State ported here becomes a field of an owner struct.

mod local;

pub(crate) use local::{local, TransientLane, REPLY_MAIN_SLOT};
