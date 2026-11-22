//! Caller outputs win32k writes into the shared argument page, returned on every completion
//! path (#421).
//!
//! The syscall route stages each output-carrying service's caller buffers in provider memory
//! and records a [`StagedOutput`] plan. One rule then applies however the dispatch completes:
//!
//! * immediately: [`StagedOutput::copy_back`] over the live page;
//! * after parking on a provider wait, an LPC wait or a user callback: the route retains the
//!   plan ([`retain_parked`]), the provider's completion captures the plan's ranges before the
//!   page is reused ([`capture_completed`]), and the completed-dispatch consumer copies them back
//!   ([`copy_back_completed`]). A completion whose output was not captured fails instead of
//!   reporting success over an unwritten caller buffer.
//!
//! Message and paint outputs use their own leased stages, retained the same way by
//! `DispatchOutputStage`; they are not staged here.

use super::*;
use nt_kernel_exec::gdi_text_metrics::{TextMetricsCall, TextMetricsSummary};
use nt_kernel_exec::user_window_list::BuildHwndListCall;
use nt_kernel_exec::win32k_staged_output::{
    OutputRange, ParkedStagedOutputs, StageBytes, StagedOutputPlan, TakeError,
};

/// The executive's view of the shared argument frames as the provider left them.
struct LiveStage;

impl StageBytes for LiveStage {
    fn bytes(&self, va: u64, len: usize) -> Option<&[u8]> {
        let start = win32k_subsystem::WIN32K_ARG_VADDR;
        let end = start + win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000;
        let last = va.checked_add(len as u64)?;
        (va >= start && last <= end)
            .then(|| unsafe { core::slice::from_raw_parts(va as *const u8, len) })
    }
}

/// One output-carrying service's caller buffers and their staged stand-ins.
#[derive(Clone, Copy)]
pub(crate) enum StagedOutput {
    /// NtGdiOpenDCW's `pUMdhpdev`.
    OpenDcw { client: u64, staged: u64 },
    /// NtUserBuildHwndList's handle list and needed count.
    BuildHwndList(BuildHwndListCall),
    /// NtUserGetIconInfo's ICONINFO, bpp and module/resource names.
    IconInfo(CapturedGetIconInfo),
    /// NtGdiGetTextMetricsW's TMW_INTERNAL.
    TextMetrics(TextMetricsCall),
    /// NtGdiGetTextExtent's SIZE.
    TextExtent { client_size: u64, staged_size: u64 },
    /// NtGdiGetTextExtentExW's fit count, dx array and SIZE.
    TextExtentEx {
        client_fit: u64,
        staged_fit: u64,
        client_dx: u64,
        staged_dx: u64,
        client_size: u64,
        staged_size: u64,
        dx_bytes: usize,
    },
    /// NtGdiGetCharWidthW's width buffer.
    CharWidth { client: u64, staged: u64, bytes: usize },
    /// NtGdiCreateDIBSection's `ppvBits`.
    DibSectionBits { client: u64, staged: u64 },
    /// NtUserMessageCall's `ResultInfo`.
    MessageCall { client: u64, staged: u64, bytes: usize },
}

fn unicode_string_ranges(capture: &CapturedUnicodeStringOut, out: &mut Vec<OutputRange>) {
    out.push(OutputRange { va: capture.desc_out, len: 16 });
    if capture.buffer_cap != 0 {
        out.push(OutputRange { va: capture.buffer_out, len: capture.buffer_cap as usize });
    }
}

impl StagedOutputPlan for StagedOutput {
    fn output_ranges(&self, out: &mut Vec<OutputRange>) {
        let mut push = |va: u64, len: usize| {
            if va != 0 && len != 0 {
                out.push(OutputRange { va, len });
            }
        };
        match *self {
            Self::OpenDcw { staged, .. } | Self::DibSectionBits { staged, .. } => push(staged, 8),
            Self::BuildHwndList(_) => push(
                win32k_subsystem::WIN32K_ARG_VADDR,
                WIN32K_BUILD_HWND_LIST_COUNT_OFFSET as usize + 4,
            ),
            Self::IconInfo(capture) => {
                if capture.iconinfo_client != 0 {
                    push(capture.iconinfo_out, GET_ICON_INFO_ICONINFO_BYTES);
                }
                if capture.bpp_client != 0 {
                    push(capture.bpp_out, 4);
                }
                for string in [capture.module, capture.resource].into_iter().flatten() {
                    unicode_string_ranges(&string, out);
                }
            }
            Self::TextMetrics(call) => push(win32k_subsystem::WIN32K_ARG_VADDR, call.bytes),
            Self::TextExtent { staged_size, .. } => push(staged_size, 8),
            Self::TextExtentEx { staged_fit, staged_dx, staged_size, dx_bytes, .. } => {
                push(staged_size, 8);
                push(staged_fit, 4);
                push(staged_dx, dx_bytes);
            }
            Self::CharWidth { staged, bytes, .. } | Self::MessageCall { staged, bytes, .. } => {
                push(staged, bytes)
            }
        }
    }
}

/// A caller write that could not be made.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CopyBackFailed;

impl StagedOutput {
    pub(crate) fn label(&self) -> &'static [u8] {
        match self {
            Self::OpenDcw { .. } => b"NtGdiOpenDCW",
            Self::BuildHwndList(_) => b"NtUserBuildHwndList",
            Self::IconInfo(_) => b"NtUserGetIconInfo",
            Self::TextMetrics(_) => b"NtGdiGetTextMetricsW",
            Self::TextExtent { .. } => b"NtGdiGetTextExtent",
            Self::TextExtentEx { .. } => b"NtGdiGetTextExtentExW",
            Self::CharWidth { .. } => b"NtGdiGetCharWidthW",
            Self::DibSectionBits { .. } => b"NtGdiCreateDIBSection",
            Self::MessageCall { .. } => b"NtUserMessageCall",
        }
    }

    /// The service result the caller sees when its output cannot be returned.
    pub(crate) fn failure_result(&self) -> (u64, bool) {
        match self {
            Self::OpenDcw { .. } => (0xC000_0001, false),
            Self::BuildHwndList(_) => (0xC000_0005, false),
            _ => (0, true),
        }
    }

    /// Return the outputs win32k produced for `result`, reading the staged bytes from `stage`.
    pub(crate) unsafe fn copy_back(
        &self,
        stage: &impl StageBytes,
        result: u64,
        pi: usize,
        path: &[u8],
        scratch_base: u64,
    ) -> Result<(), CopyBackFailed> {
        let pid = pi as u64;
        // `write` admits the caller's access first, as the services' scalar outputs always
        // have; `copy` writes the larger buffers through the mapped frames directly.
        let out = |client: u64, staged: u64, len: usize, admitted: bool| -> bool {
            client == 0
                || len == 0
                || stage.bytes(staged, len).is_some_and(|bytes| {
                    if admitted {
                        img_spawn::client_write_mapped(pid, client, bytes, scratch_base)
                    } else {
                        img_spawn::client_copyout_mapped(pid, client, bytes, scratch_base)
                    }
                })
        };
        let write = |client: u64, staged: u64, len: usize| out(client, staged, len, true);
        let copy = |client: u64, staged: u64, len: usize| out(client, staged, len, false);
        let ok = match *self {
            Self::OpenDcw { client, staged } => result == 0 || write(client, staged, 8),
            Self::DibSectionBits { client, staged } => result == 0 || copy(client, staged, 8),
            Self::BuildHwndList(call) => {
                let list = win32k_subsystem::WIN32K_ARG_VADDR;
                match stage.read_u32(list + WIN32K_BUILD_HWND_LIST_COUNT_OFFSET) {
                    None => false,
                    Some(required) => {
                        let copy_out = call.copy_out(
                            result as u32, required, WIN32K_BUILD_HWND_LIST_MAX_HANDLES,
                        );
                        let needed_ok = copy_out.needed.is_none_or(|needed| {
                            img_spawn::client_write_mapped(
                                pid, call.needed, &needed.to_le_bytes(), scratch_base,
                            )
                        });
                        needed_ok && copy(call.list, list, copy_out.handles * 8)
                    }
                }
            }
            Self::IconInfo(capture) => result == 0 || copy_back_icon_info(stage, pid, capture, scratch_base),
            Self::TextMetrics(call) => return copy_back_text_metrics(stage, pi, call, result, path, scratch_base),
            Self::TextExtent { client_size, staged_size } => {
                result == 0 || write(client_size, staged_size, 8)
            }
            Self::TextExtentEx {
                client_fit, staged_fit, client_dx, staged_dx, client_size, staged_size, dx_bytes,
            } => {
                result == 0
                    || (write(client_size, staged_size, 8)
                        && write(client_fit, staged_fit, 4)
                        && copy(client_dx, staged_dx, dx_bytes))
            }
            Self::CharWidth { client, staged, bytes } => result == 0 || copy(client, staged, bytes),
            Self::MessageCall { client, staged, bytes } => copy(client, staged, bytes),
        };
        if ok {
            return Ok(());
        }
        let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
        if failures < 8 {
            print_str(b"[win32k-svc] ");
            print_str(self.label());
            print_str(b" copy-out failed pi=");
            print_u64(pid);
            print_str(b" path=");
            print_str(path);
            print_str(b"\n");
        }
        Err(CopyBackFailed)
    }
}

/// Immediate completion: copy back from the live page.
pub(crate) unsafe fn copy_back_immediate(
    plan: StagedOutput,
    result: u64,
    pi: usize,
    scratch_base: u64,
) -> Result<(), CopyBackFailed> {
    plan.copy_back(&LiveStage, result, pi, b"immediate", scratch_base)
}

static mut PARKED: ParkedStagedOutputs<StagedOutput> = ParkedStagedOutputs::new();

fn parked() -> &'static mut ParkedStagedOutputs<StagedOutput> {
    unsafe { &mut *core::ptr::addr_of_mut!(PARKED) }
}

/// The dispatch parked before returning; its caller is still owed `plan`'s outputs.
pub(crate) fn retain_parked(dispatch_id: u64, plan: StagedOutput) {
    if parked().retain(dispatch_id, plan).is_err() {
        print_str(b"[win32k-staged-output] dispatch already retains a plan id=");
        print_u64(dispatch_id);
        print_str(b"\n");
    }
}

/// The provider finished a parked dispatch: bind its outputs before the page is reused.
pub(crate) unsafe fn capture_completed(dispatch_id: u64) {
    let captured = parked().capture(dispatch_id, |va, out| {
        LiveStage.bytes(va, out.len()).map(|bytes| out.copy_from_slice(bytes)).is_some()
    });
    if !captured {
        print_str(b"[win32k-staged-output] completion outside the staged page id=");
        print_u64(dispatch_id);
        print_str(b"\n");
    }
}

/// The completed-dispatch consumer's copy-back. `false` when the caller's outputs cannot be
/// returned; the completion then fails rather than report the provider's result.
pub(crate) unsafe fn copy_back_completed(
    dispatch_id: u64,
    result: u64,
    pi: usize,
    scratch_base: u64,
) -> bool {
    match parked().take(dispatch_id) {
        None => true,
        Some(Ok((plan, captured))) => {
            plan.copy_back(&captured, result, pi, b"completed", scratch_base).is_ok()
        }
        Some(Err(TakeError::Uncaptured)) => {
            print_str(b"[win32k-staged-output] completed dispatch lost its staged output id=");
            print_u64(dispatch_id);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b"\n");
            false
        }
    }
}

unsafe fn copy_back_unicode_string_output(
    stage: &impl StageBytes,
    pi: u64,
    capture: CapturedUnicodeStringOut,
    scratch_base: u64,
) -> bool {
    let Some(staged) = stage.bytes(capture.desc_out, 16) else { return false };
    let length = u16::from_le_bytes([staged[0], staged[1]]);
    let maximum = u16::from_le_bytes([staged[2], staged[3]]);
    let staged_buffer = u64::from_le_bytes(staged[8..16].try_into().unwrap());

    let mut out_desc = capture.original_desc;
    out_desc[0..2].copy_from_slice(&length.to_le_bytes());
    let client_maximum =
        if staged_buffer == capture.buffer_out && length != 0 && maximum == capture.buffer_cap {
            capture.maximum_client
        } else {
            maximum
        };
    out_desc[2..4].copy_from_slice(&client_maximum.to_le_bytes());

    let (client_buffer, buffer_ok) = if staged_buffer == capture.buffer_out {
        if length == 0 {
            (capture.buffer_client, true)
        } else if capture.buffer_client == 0
            || length > capture.maximum_client
            || length > capture.buffer_cap
        {
            (capture.buffer_client, false)
        } else {
            (
                capture.buffer_client,
                stage.bytes(capture.buffer_out, length as usize).is_some_and(|bytes| {
                    img_spawn::client_copyout_mapped(pi, capture.buffer_client, bytes, scratch_base)
                }),
            )
        }
    } else if is_int_resource_value(staged_buffer) || staged_buffer == 0 {
        (staged_buffer, true)
    } else {
        (capture.buffer_client, false)
    };
    out_desc[8..16].copy_from_slice(&client_buffer.to_le_bytes());

    buffer_ok && img_spawn::client_write_mapped(pi, capture.desc_client, &out_desc, scratch_base)
}

unsafe fn copy_back_icon_info(
    stage: &impl StageBytes,
    pi: u64,
    capture: CapturedGetIconInfo,
    scratch_base: u64,
) -> bool {
    let copy = |client: u64, staged: u64, len: usize| {
        client == 0
            || stage.bytes(staged, len).is_some_and(|bytes| {
                img_spawn::client_copyout_mapped(pi, client, bytes, scratch_base)
            })
    };
    copy(capture.iconinfo_client, capture.iconinfo_out, GET_ICON_INFO_ICONINFO_BYTES)
        && copy(capture.bpp_client, capture.bpp_out, 4)
        && capture.module.is_none_or(|module| {
            copy_back_unicode_string_output(stage, pi, module, scratch_base)
        })
        && capture.resource.is_none_or(|resource| {
            copy_back_unicode_string_output(stage, pi, resource, scratch_base)
        })
}

/// Per-process budget for successful GetTextMetricsW results; zero cells and failures are
/// always traced, so a console that divides by its font cell leaves the cause in the log.
static TEXT_METRICS_RESULT_TRACE: [core::sync::atomic::AtomicU8; 64] =
    [const { core::sync::atomic::AtomicU8::new(0) }; 64];
const TEXT_METRICS_SUCCESS_TRACE_PER_PROCESS: u8 = 2;

/// NtGdiGetTextMetricsW returns exactly `cj` bytes, only when win32k returned TRUE.
unsafe fn copy_back_text_metrics(
    stage: &impl StageBytes,
    pi: usize,
    call: TextMetricsCall,
    result: u64,
    path: &[u8],
    scratch_base: u64,
) -> Result<(), CopyBackFailed> {
    let bytes = call.copy_back_bytes(result);
    let output = if bytes == 0 {
        Some(&[][..])
    } else {
        stage.bytes(win32k_subsystem::WIN32K_ARG_VADDR, bytes)
    };
    let summary = output.and_then(TextMetricsSummary::read);
    let copied = bytes == 0
        || output.is_some_and(|output| {
            img_spawn::client_write_mapped(pi as u64, call.output, output, scratch_base)
        });
    let suspicious = bytes == 0 || !copied || summary.is_none_or(|summary| summary.has_zero_cell());
    let budget = &TEXT_METRICS_RESULT_TRACE[pi.min(TEXT_METRICS_RESULT_TRACE.len() - 1)];
    if suspicious || budget.fetch_add(1, Ordering::Relaxed) < TEXT_METRICS_SUCCESS_TRACE_PER_PROCESS {
        let print_i32 = |value: i32| {
            if value < 0 {
                print_str(b"-");
            }
            print_u64(u64::from(value.unsigned_abs()));
        };
        print_str(b"[gdi-text-metrics] pi=");
        print_u64(pi as u64);
        print_str(b" path=");
        print_str(path);
        print_str(b" result=0x");
        print_hex(result as u32);
        print_str(b" cj=");
        print_u64(call.bytes as u64);
        print_str(b" copied=");
        print_u64(copied as u64);
        if let Some(summary) = summary {
            print_str(b" tmHeight=");
            print_i32(summary.height);
            print_str(b" tmExternalLeading=");
            print_i32(summary.external_leading);
            print_str(b" tmAveCharWidth=");
            print_i32(summary.ave_char_width);
            print_str(b" tmMaxCharWidth=");
            print_i32(summary.max_char_width);
        }
        print_str(b"\n");
    }
    if copied { Ok(()) } else { Err(CopyBackFailed) }
}
