//! Copied image-view observations; these records never authorize mapping or retirement.

use super::*;
use core::fmt::Write;

#[derive(Clone, Copy)]
pub(super) struct ImageViewTransition {
    caller_pi: usize,
    caller: Option<nt_memory_manager::ProcessIdentity>,
    observed_tid: u64,
    thread: Option<nt_process::ThreadLifetime>,
    view: NativeImageViewDescriptor,
    source: Option<nt_memory_manager::SectionFileIdentity>,
    source_extent: Option<u64>,
    preferred: Option<u64>,
}

pub(super) fn capture_image_view_transition(
    handler: &ExecNtHandler,
    view: NativeImageViewDescriptor,
) -> ImageViewTransition {
    let source = handler.image_sections.source_for_view(view.view);
    ImageViewTransition {
        caller_pi: handler.pi,
        caller: handler.capture_process_identity(handler.pi),
        observed_tid: handler.current_tid as u64,
        thread: u32::try_from(handler.current_tid)
            .ok()
            .and_then(|tid| handler.pm.thread_lifetime(tid)),
        view,
        source: source.and_then(|source| source.backing.file),
        source_extent: source.map(|source| source.backing.file_extent),
        preferred: source.map(|source| source.layout.headers().image_base),
    }
}

#[derive(Clone, Copy)]
pub(super) enum ImageViewTransitionKind {
    Mapped,
    Unmapped,
}

pub(super) fn emit_image_view_transition(
    capture: ImageViewTransition,
    kind: ImageViewTransitionKind,
    live_views: usize,
) {
    let phase = match kind {
        ImageViewTransitionKind::Mapped => "mapped",
        ImageViewTransitionKind::Unmapped => "unmapped",
    };
    let view = capture.view;
    let mut record = nt_printf::record::RecordBuffer::<2048>::new();
    let _ = writeln!(
        record,
        "[image-view-transition] phase={phase} caller-pi={} caller={:?} observed-tid={} thread={:?} target-pi={} target={:?} view={:?} pml4=0x{:016x} base=0x{:016x} size=0x{:x} section-offset=0x{:x} source={:?} source-extent={:?} preferred={:?} live-views={live_views}",
        capture.caller_pi,
        capture.caller,
        capture.observed_tid,
        capture.thread,
        view.pi,
        view.process,
        view.view,
        view.pml4,
        view.base,
        view.size,
        view.section_offset,
        capture.source,
        capture.source_extent,
        capture.preferred,
    );
    sel4_rt::print_record(if record.overflowed() {
        b"[image-view-transition] record-truncated\n"
    } else {
        record.bytes()
    });
}
