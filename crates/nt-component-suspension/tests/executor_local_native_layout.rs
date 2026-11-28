//! Compile and run the executive's actual executor-local module on the host without changing FS.

// The native module's constructor uses this boot scratch constant.
const SMSS_SCRATCH_BASE: u64 = 0x1000;

#[allow(dead_code, unexpected_cfgs)]
#[path = "../../../components/ntos-executive/src/executor/local.rs"]
mod native_local;
