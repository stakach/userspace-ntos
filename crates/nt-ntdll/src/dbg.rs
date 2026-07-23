//! `Dbg*` — the ntdll debug-print + debugger-client surface (12 imported exports).
//!
//! Two families:
//!
//! * **Debug print** — `DbgPrint` / `DbgPrintEx` / `vDbgPrintEx` / `vDbgPrintExWithPrefix` /
//!   `DbgPrompt`. These format a message (reusing the 2b `_snprintf`-core, [`crate::crt::format`])
//!   and hand it to the kernel's debug service. On our kernel that path is the **`int 0x2d`
//!   DebugService** (`DbgPrint` → `DebugPrint` with the message in registers), which the executive
//!   forwards to serial (see `project_smss_sec_image`). `DbgPrintEx` adds a **component-id + level**
//!   filter (only prints if the component/level filter is enabled) — the filtering logic is
//!   host-tested here; the actual `int 0x2d` is target-gated. `DbgPrompt` writes a prompt then reads
//!   a one-line response (the RtlAssert 'Break/Ignore' path) — the response goes in **`r8`** on our
//!   kernel (the load-bearing DbgPrompt fix from `project_smss_sec_image`).
//! * **DbgUi\*** — the user-mode debugger *client* (`DbgUiConnectToDbg`, `DbgUiWaitStateChange`,
//!   `DbgUiContinue`, `DbgUiDebugActiveProcess`, `DbgUiStopDebugging`,
//!   `DbgUiConvertStateChangeStructure`, `DbgUiGetThreadDebugObject`, `DbgUiIssueRemoteBreakin`).
//!   These wrap the `NtDebug*`/`NtCreateDebugObject` syscalls + the per-thread debug-object TEB slot.
//!   The state-change *conversion* logic is host-testable; the syscalls are transport seams.
//! * **Breakpoints** — `DbgBreakPoint` / `DbgUserBreakPoint` = `int3` (target-gated).

use alloc::vec::Vec;

use crate::crt::{format, FmtArg};

/// `DEBUGLEVEL` values used by `DbgPrintEx` (the `Level` argument, WinDbg's mask semantics). A level
/// `< 32` is a bit index into the component's filter mask; `>= 32` is a raw importance value where
/// only `DPFLTR_ERROR_LEVEL`/`WARNING`/`TRACE`/`INFO` are recognised.
pub mod level {
    /// `DPFLTR_ERROR_LEVEL`.
    pub const ERROR: u32 = 0;
    /// `DPFLTR_WARNING_LEVEL`.
    pub const WARNING: u32 = 1;
    /// `DPFLTR_TRACE_LEVEL`.
    pub const TRACE: u32 = 2;
    /// `DPFLTR_INFO_LEVEL`.
    pub const INFO: u32 = 3;
    /// The `DPFLTR_MASK` bit: when set in `Level`, the low bits are a raw mask, not a bit index.
    pub const MASK: u32 = 0x8000_0000;
}

/// The per-component debug-print filter mask (WinDbg `Kd_*_Mask`). Real ntdll reads these from the
/// `HKLM\...\Debug Print Filter` registry key at init; we model the mask so the *filtering decision*
/// is host-tested. Default (all zero) = only unconditional `DbgPrint` and `ERROR`-level output.
#[derive(Copy, Clone, Debug, Default)]
pub struct ComponentFilter {
    /// The component's enabled-level bit mask.
    pub mask: u32,
}

impl ComponentFilter {
    /// Whether a `DbgPrintEx(component, level, …)` call with this `level` should actually print,
    /// given this component's filter `mask`. Mirrors `NtQueryDebugFilterState`:
    /// - `ERROR` level (0) always prints (the default-on floor).
    /// - a `level < 32` prints iff bit `level` is set in the mask.
    /// - a `level` with the `MASK` bit prints iff `(level & mask) != 0`.
    pub fn should_print(&self, level: u32) -> bool {
        if level == self::level::ERROR {
            return true;
        }
        if level & self::level::MASK != 0 {
            (level & !self::level::MASK) & self.mask != 0
        } else if level < 32 {
            self.mask & (1u32 << level) != 0
        } else {
            // Out-of-range raw importance: only ERROR/WARNING/TRACE/INFO are meaningful; anything
            // else defaults off unless the mask opts in via bit 0.
            self.mask & 1 != 0
        }
    }
}

/// Convert an `NtQueryDebugFilterState`/`NtSetDebugFilterState` level to the stored mask bitfield.
pub fn debug_filter_level_mask(level: u32) -> u32 {
    let mask = if level < 32 { 1u32 << level } else { level };
    mask & !self::level::MASK
}

/// Query a debug-filter mask pair using the ReactOS kernel contract: a message is enabled if either
/// the system-wide mask or the component mask contains the converted level bit.
pub fn debug_filter_state(system_mask: u32, component_mask: u32, level: u32) -> bool {
    let mask = debug_filter_level_mask(level);
    mask != 0 && ((system_mask | component_mask) & mask) != 0
}

/// Render a `DbgPrint`-style message: `format` + `args` → the bytes that would be emitted to the
/// debug service. Pure; the target-side `emit` hands these to `int 0x2d`.
pub fn render(fmt: &[u8], args: &[FmtArg]) -> Vec<u8> {
    format(fmt, args)
}

/// Render a `vDbgPrintExWithPrefix` message: `prefix` prepended to the formatted body (the exact
/// shape `vDbgPrintExWithPrefix(Prefix, ComponentId, Level, Format, ap)` produces before it hits the
/// filter + the debug service).
pub fn render_with_prefix(prefix: &[u8], fmt: &[u8], args: &[FmtArg]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + fmt.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&format(fmt, args));
    out
}

/// Apply the native fixed-buffer overflow policy used by the DbgPrint family.
///
/// A successful render emits its exact byte count. When formatting overflows, ntdll replaces the
/// final two buffer bytes with a newline and NUL and emits every byte except that terminator.
pub fn finalize_print_buffer(buffer: &mut [u8], rendered_len: usize, overflowed: bool) -> usize {
    if overflowed && buffer.len() >= 2 {
        let end = buffer.len();
        buffer[end - 2] = b'\n';
        buffer[end - 1] = 0;
        end - 1
    } else {
        rendered_len.min(buffer.len())
    }
}

fn push_hex(out: &mut Vec<u8>, value: u64, minimum_digits: usize) {
    let significant_digits = if value == 0 {
        1
    } else {
        ((64 - value.leading_zeros() as usize) + 3) / 4
    };
    let digits = significant_digits.max(minimum_digits);
    for index in (0..digits).rev() {
        let digit = ((value >> (index * 4)) & 0xf) as u8;
        out.push(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
}

/// Render the diagnostic emitted by `RtlApplicationVerifierStop` before it raises a debugger
/// breakpoint. The value descriptions are narrow strings, matching the native ten-argument ABI.
pub fn render_application_verifier_stop(
    code: usize,
    process_id: usize,
    message: &[u8],
    values: &[(usize, &[u8]); 4],
) -> Vec<u8> {
    const BANNER: &[u8] = b"**************************************************\n";

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(BANNER);
    out.extend_from_slice(b"VERIFIER STOP ");
    push_hex(&mut out, code as u64, 8);
    out.extend_from_slice(b": pid ");
    push_hex(&mut out, process_id as u64, 4);
    out.extend_from_slice(b":  ");
    out.extend_from_slice(message);
    out.push(b'\n');

    for (value, description) in values {
        out.extend_from_slice(b"    0x");
        push_hex(&mut out, *value as u64, 16);
        out.extend_from_slice(b" : ");
        out.extend_from_slice(description);
        out.push(b'\n');
    }
    out.extend_from_slice(BANNER);
    out
}

/// `DbgPrintEx(ComponentId, Level, Format, …)` decision + render: returns `Some(bytes)` if the
/// component/level filter passes, else `None` (suppressed — NOT printed, and NOT faked). The caller
/// emits `Some` via the debug service.
pub fn print_ex(
    filter: ComponentFilter,
    level: u32,
    fmt: &[u8],
    args: &[FmtArg],
) -> Option<Vec<u8>> {
    if filter.should_print(level) {
        Some(render(fmt, args))
    } else {
        None
    }
}

/// The `DbgPrompt` response shape: the prompt string is written to the debug service, and up to
/// `response_len` bytes of a reply are read back. On our kernel the reply buffer pointer is passed in
/// **`r8`** (the load-bearing fix from `project_smss_sec_image` — the x64 `DbgPrompt` DebugService
/// response goes in R8, not RCX). This models the request/response pair; the actual DebugService
/// round-trip is target-gated ([`emit_prompt`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptRequest {
    /// The prompt bytes to display.
    pub prompt: Vec<u8>,
    /// The maximum reply length the caller will accept.
    pub response_len: usize,
}

/// Build a `DbgPrompt(Prompt, Response, Length)` request. The response buffer is filled by the debug
/// service (target-side); here we capture the request so tests can assert its shape.
pub fn prompt(prompt_bytes: &[u8], response_len: usize) -> PromptRequest {
    PromptRequest {
        prompt: prompt_bytes.to_vec(),
        response_len,
    }
}

/// The `int 0x2d` DebugService `ServiceClass` codes our kernel emulates (see
/// `project_smss_sec_image`: the executive services `PRINT`/`PROMPT` and forwards to serial).
pub mod service {
    /// `BREAKPOINT_PRINT` — `DbgPrint` (message → serial).
    pub const PRINT: u32 = 1;
    /// `BREAKPOINT_PROMPT` — `DbgPrompt` (message → serial, response ← R8).
    pub const PROMPT: u32 = 2;
    /// `BREAKPOINT_LOAD_SYMBOLS` / `UNLOAD_SYMBOLS` — no-ops on our kernel.
    pub const LOAD_SYMBOLS: u32 = 3;
    /// `BREAKPOINT_UNLOAD_SYMBOLS`.
    pub const UNLOAD_SYMBOLS: u32 = 4;
}

// --- Target-only breakpoint + emit primitives -------------------------------------------------

/// `DbgBreakPoint` / `DbgUserBreakPoint` — a debugger breakpoint (`int3`).
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn breakpoint() {
    // SAFETY: `int3` raises #BP; on our kernel it faults through the debug path. No memory touched.
    unsafe { core::arch::asm!("int3", options(nomem, nostack, preserves_flags)) };
}

/// Host build: no `int3` available; breakpoint is a no-op (the emit path is target-only).
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn breakpoint() {}

/// Emit a rendered debug message to the kernel debug service (`int 0x2d`, `ServiceClass = PRINT`).
/// Message pointer in `rcx`, length in `rdx` (the ntdll `DebugPrint` convention our executive
/// forwards to serial). Target-only; the host has no debug service.
///
/// # Safety
/// Issues `int 0x2d` with `rcx`/`rdx`/`rax` set. `msg` must point to `len` valid bytes.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn emit(msg: *const u8, len: usize) {
    core::arch::asm!(
        "int 0x2d",
        in("eax") service::PRINT,
        in("rcx") msg,
        in("rdx") len,
        options(nostack, preserves_flags),
    );
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn error_level_always_prints() {
        let f = ComponentFilter::default();
        assert!(f.should_print(level::ERROR));
        // Non-error levels suppressed with an all-zero mask.
        assert!(!f.should_print(level::WARNING));
        assert!(!f.should_print(level::INFO));
    }

    #[test]
    fn level_bit_filtering() {
        // Enable WARNING (bit 1) + INFO (bit 3).
        let f = ComponentFilter {
            mask: (1 << level::WARNING) | (1 << level::INFO),
        };
        assert!(f.should_print(level::WARNING));
        assert!(f.should_print(level::INFO));
        assert!(!f.should_print(level::TRACE));
    }

    #[test]
    fn masked_raw_importance() {
        let f = ComponentFilter { mask: 0b0100 };
        assert!(f.should_print(level::MASK | 0b0100));
        assert!(!f.should_print(level::MASK | 0b0010));
    }

    #[test]
    fn debug_filter_query_uses_system_or_component_mask() {
        assert_eq!(debug_filter_level_mask(level::ERROR), 1);
        assert_eq!(debug_filter_level_mask(level::MASK | 0b0100), 0b0100);
        assert!(debug_filter_state(1, 0, level::ERROR));
        assert!(debug_filter_state(0, 1 << level::WARNING, level::WARNING));
        assert!(!debug_filter_state(0, 0, level::TRACE));
    }

    #[test]
    fn print_ex_suppresses_without_faking() {
        let f = ComponentFilter::default();
        // ERROR prints.
        assert_eq!(
            print_ex(f, level::ERROR, b"boom %d", &[FmtArg::Int(1)]),
            Some(b"boom 1".to_vec())
        );
        // TRACE suppressed → None (NOT an empty "success").
        assert_eq!(print_ex(f, level::TRACE, b"noisy", &[]), None);
    }

    #[test]
    fn render_and_prefix() {
        assert_eq!(render(b"pid=%d", &[FmtArg::Int(4)]), b"pid=4");
        assert_eq!(
            render_with_prefix(b"[smss] ", b"start %s", &[FmtArg::Str(b"csrss\0")]),
            b"[smss] start csrss"
        );
    }

    #[test]
    fn debug_print_success_preserves_rendered_length() {
        let mut buffer = [b'x'; 8];
        assert_eq!(finalize_print_buffer(&mut buffer, 3, false), 3);
        assert_eq!(&buffer[..3], b"xxx");
    }

    #[test]
    fn debug_print_overflow_ends_with_newline_and_hidden_nul() {
        let mut buffer = [b'x'; 8];
        assert_eq!(finalize_print_buffer(&mut buffer, 8, true), 7);
        assert_eq!(&buffer[..7], b"xxxxxx\n");
        assert_eq!(buffer[7], 0);
    }

    #[test]
    fn application_verifier_stop_matches_native_shape() {
        let rendered = render_application_verifier_stop(
            0x2a,
            0x19,
            b"bad handle",
            &[
                (1, b"first"),
                (0xfeed, b"second"),
                (0, b"third"),
                (usize::MAX, b"fourth"),
            ],
        );
        assert_eq!(
            rendered,
            concat!(
                "**************************************************\n",
                "VERIFIER STOP 0000002a: pid 0019:  bad handle\n",
                "    0x0000000000000001 : first\n",
                "    0x000000000000feed : second\n",
                "    0x0000000000000000 : third\n",
                "    0xffffffffffffffff : fourth\n",
                "**************************************************\n",
            )
            .as_bytes()
        );
    }

    #[test]
    fn application_verifier_stop_does_not_truncate_large_ids() {
        let rendered = render_application_verifier_stop(
            0x1_0000_0000,
            0x1_0000,
            b"message",
            &[(0, b"one"), (0, b"two"), (0, b"three"), (0, b"four")],
        );
        assert!(rendered
            .windows(b"VERIFIER STOP 100000000: pid 10000".len())
            .any(|window| window == b"VERIFIER STOP 100000000: pid 10000"));
    }

    #[test]
    fn prompt_request_shape() {
        let r = prompt(b"Break, Ignore, Proceed (bip)? ", 4);
        assert_eq!(r.response_len, 4);
        assert_eq!(r.prompt.len(), 30);
        // The response buffer is filled by the DebugService (R8 on our kernel) — modelled, not faked.
        assert_eq!(service::PROMPT, 2);
    }

    #[test]
    fn breakpoint_is_callable_on_host() {
        // On the host this is a no-op; the assertion is that it links + returns.
        breakpoint();
    }
}
