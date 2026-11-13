//! Executors: the threads that run executive code (issue #382, stage 1).
//!
//! This is the first directory of the executive's target layout. `local.rs` holds the
//! executor-local context. The other files are the hoisted service loop: `LoopState`
//! (`loop_state.rs`), one turn (`body.rs`), between-event maintenance, admission, one file
//! per event arm, and the receive and park helpers. Those files are declared from
//! `service_sec_image.rs`, not from here, because the loop still reaches that module's
//! private helpers; they move under this module as those helpers are ported. The pool and the
//! yield/resume glue come with later steps. There is still exactly one executor, the root TCB.
//!
//! Layout rule, enforced in CI by `scripts/check_executive_layout_statics.sh`: the only
//! `static` permitted under the target-layout directories is the executor-local block in
//! `local.rs`. State ported here becomes a field of an owner struct.

mod local;

pub(crate) use local::{local, TransientLane, REPLY_MAIN_SLOT};
