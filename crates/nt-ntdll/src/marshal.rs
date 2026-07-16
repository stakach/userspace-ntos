//! Argument marshalling for the non-trap transports (seL4 `Call` / SURT ring).
//!
//! The x86-trap backend does **not** need this: for a raw `syscall`, args 1..=4 are in
//! `r10, rdx, r8, r9` and args 5.. stay on the caller's stack, where the kernel reads them directly
//! (there is no explicit stack thunk — the trap ABI IS the calling convention). See
//! [`crate::transport`].
//!
//! The seL4/SURT backends are different: they must **gather every argument** — including the ones
//! the compiler left on the caller's stack — into a self-contained IPC message / ring entry, because
//! the servicing endpoint is reached by a capability invocation, not by faulting the kernel into the
//! caller's stack frame. This module is that gatherer.
//!
//! It is arity-driven: each `Nt*` service has a known parameter count ([`nt_syscall_abi::argc_of`]),
//! so the marshaller pulls exactly that many register-width slots from an [`ArgSource`] (which
//! abstracts "the first four are in registers, the rest are at `[rsp + 0x28 + 8*i]`"). Host tests
//! drive it with a mock [`SliceArgSource`], including a >4-arg service, and assert the produced
//! message is exactly the gathered arg vector — no faked send.

use alloc::vec::Vec;
use nt_syscall_abi::argc_of;

/// The stack offset (in register-width slots) at which the 5th native-syscall argument lives,
/// relative to the base the [`ArgSource`] presents. On x64 the first four integer args are in
/// registers; args 5.. sit on the stack above the return address + shadow space. An [`ArgSource`]
/// presents its stack window as slot 0 = the 5th arg, so callers index it 0-based.
pub const FIRST_STACK_ARG: usize = 4;

/// A source of native-syscall arguments: the four register args plus a stack window for the rest.
///
/// The real target implementation reads `r10/rdx/r8/r9` and `[rsp + shadow]`; host tests use
/// [`SliceArgSource`]. Kept as a trait so the *gathering logic* is fully host-testable without any
/// target asm.
pub trait ArgSource {
    /// The `i`-th register arg (`0..4` → `r10, rdx, r8, r9`). Out-of-range returns `0`.
    fn reg(&self, i: usize) -> u64;
    /// The `i`-th **stack** arg (`i == 0` → the 5th native arg). Out-of-range returns `0`.
    fn stack(&self, i: usize) -> u64;
}

/// A fully-gathered syscall message: the SSN plus the exact `argc` register-width arguments, in
/// native order (arg0..argN). This is the payload a seL4 `Call` / SURT ring entry carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marshalled {
    /// The system-service number.
    pub ssn: u32,
    /// The gathered arguments, exactly `argc` of them, in native (arg0-first) order.
    pub args: Vec<u64>,
}

impl Marshalled {
    /// The number of gathered arguments.
    pub fn argc(&self) -> usize {
        self.args.len()
    }
}

/// Gather exactly `argc` arguments from `src` (registers first, then the stack window) into a
/// [`Marshalled`] message for `ssn`. This is the core the non-trap backends call before sending.
pub fn marshal(ssn: u32, argc: usize, src: &dyn ArgSource) -> Marshalled {
    let mut args = Vec::with_capacity(argc);
    let mut i = 0;
    while i < argc {
        let v = if i < FIRST_STACK_ARG {
            src.reg(i)
        } else {
            src.stack(i - FIRST_STACK_ARG)
        };
        args.push(v);
        i += 1;
    }
    Marshalled { ssn, args }
}

/// Marshal by service name: resolves the arity via the shared ABI table ([`argc_of`]) — the
/// convenience entry point a named stub uses. Unknown names sweep `MAX_STUB_ARGS` (conservative;
/// never silently drops args).
pub fn marshal_named(name: &str, ssn: u32, src: &dyn ArgSource) -> Marshalled {
    marshal(ssn, argc_of(name) as usize, src)
}

/// A host-test [`ArgSource`] backed by two slices (the register window + the stack window). Also
/// used as the shape a real target `ArgSource` mirrors.
#[derive(Clone, Debug)]
pub struct SliceArgSource<'a> {
    /// The register args (`r10, rdx, r8, r9` — up to 4 meaningful).
    pub regs: &'a [u64],
    /// The stack args (the 5th native arg onward).
    pub stack: &'a [u64],
}

impl ArgSource for SliceArgSource<'_> {
    fn reg(&self, i: usize) -> u64 {
        self.regs.get(i).copied().unwrap_or(0)
    }
    fn stack(&self, i: usize) -> u64 {
        self.stack.get(i).copied().unwrap_or(0)
    }
}

/// A simple [`ArgSource`] over one flat slice in native arg order (arg0..argN). The first
/// [`FIRST_STACK_ARG`] elements are treated as register args, the rest as the stack window. Handy
/// when the caller already has the args in a single vector (e.g. the generic [`crate::stubs`]
/// invoke path, which passes `&[u64]`).
#[derive(Clone, Debug)]
pub struct FlatArgSource<'a>(pub &'a [u64]);

impl ArgSource for FlatArgSource<'_> {
    fn reg(&self, i: usize) -> u64 {
        self.0.get(i).copied().unwrap_or(0)
    }
    fn stack(&self, i: usize) -> u64 {
        self.0.get(FIRST_STACK_ARG + i).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn marshals_register_only_service() {
        // NtClose(Handle) — 1 arg, register only.
        let src = SliceArgSource { regs: &[0xdead], stack: &[] };
        let m = marshal_named("NtClose", 27, &src);
        assert_eq!(m.ssn, 27);
        assert_eq!(m.args, vec![0xdead]);
        assert_eq!(m.argc(), 1);
    }

    #[test]
    fn marshals_exactly_four_register_args() {
        // NtOpenProcess(Handle*, Access, ObjAttr*, ClientId*) — 4 args, all in registers.
        let src = SliceArgSource { regs: &[1, 2, 3, 4], stack: &[99, 100] };
        let m = marshal_named("NtOpenProcess", 128, &src);
        // Exactly 4 gathered; the stack window is NOT swept past the arity.
        assert_eq!(m.args, vec![1, 2, 3, 4]);
    }

    #[test]
    fn marshals_more_than_four_args_including_the_stack_tail() {
        // NtCreateFile — 11 args: 4 in registers + 7 on the stack. THIS is the >4-arg case the
        // trap backend leaves on the caller's stack but a seL4/SURT send MUST gather.
        let regs = [0xA, 0xB, 0xC, 0xD];
        let stack = [0x5, 0x6, 0x7, 0x8, 0x9, 0xA0, 0xB0]; // args 5..=11
        let src = SliceArgSource { regs: &regs, stack: &stack };
        let m = marshal_named("NtCreateFile", 39, &src);
        assert_eq!(m.argc(), 11);
        assert_eq!(m.args, vec![0xA, 0xB, 0xC, 0xD, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA0, 0xB0]);
    }

    #[test]
    fn marshals_the_widest_service() {
        // NtCreateNamedPipeFile = 14 args (the widest). 4 reg + 10 stack.
        let regs = [1, 2, 3, 4];
        let stack: [u64; 10] = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let src = SliceArgSource { regs: &regs, stack: &stack };
        let m = marshal_named("NtCreateNamedPipeFile", 46, &src);
        assert_eq!(m.argc(), 14);
        assert_eq!(m.args.last(), Some(&14));
    }

    #[test]
    fn flat_arg_source_splits_reg_and_stack() {
        // A flat native-order vector: first 4 = registers, rest = stack.
        let all = [10u64, 20, 30, 40, 50, 60];
        let src = FlatArgSource(&all);
        let m = marshal(0, 6, &src);
        assert_eq!(m.args, vec![10, 20, 30, 40, 50, 60]);
        // Reg/stack boundary respected.
        assert_eq!(src.reg(0), 10);
        assert_eq!(src.stack(0), 50); // 5th native arg
    }

    #[test]
    fn arity_bounds_the_gather_exactly() {
        // Extra register/stack values past the arity are never gathered (no over-read into
        // caller garbage).
        let src = SliceArgSource { regs: &[1, 2, 3, 4], stack: &[5, 6, 7, 8] };
        let m = marshal(0, 2, &src); // pretend a 2-arg service
        assert_eq!(m.args, vec![1, 2]);
    }
}
