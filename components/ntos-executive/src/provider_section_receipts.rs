//! Copied observations of admitted Section maps and retained cleanup, never ownership authority.

use crate::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_memory_manager::{GenericSection, SectionFileIdentity, SectionIdentity};
use nt_process::{native_handle::NativeHandleCaller, ThreadLifetime};
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};

#[derive(Clone, Copy)]
struct MappingInitiator {
    pi: usize,
    process: ProcessIdentity,
    thread: ThreadLifetime,
}

#[derive(Clone, Copy)]
pub(crate) struct MappingProvenance {
    section_index: usize,
    section_generation: u64,
    backing_kind: u8,
    file: Option<SectionFileIdentity>,
    initiator: Option<MappingInitiator>,
}

/// Copy observations at admitted map entry, before routed I/O can change ambient context.
/// An unavailable process observation is not a reason to refuse the underlying operation.
pub(crate) fn capture_mapping_provenance(
    handler: &ExecNtHandler,
    caller: NativeHandleCaller,
    identity: SectionIdentity,
    section: GenericSection,
) -> MappingProvenance {
    let initiator = handler.native_section_owner_pi(caller).ok().and_then(|pi| {
        let process = handler.capture_process_identity(pi)?;
        let thread = caller.original_thread();
        (process.pid == caller.effective_process()
            && process.pid == thread.process_id()
            && handler.pm.validate_thread_lifetime(thread))
            .then_some(MappingInitiator { pi, process, thread })
    });
    MappingProvenance {
        section_index: identity.index(),
        section_generation: section.generation,
        backing_kind: section.backing.kind,
        file: section.backing.file,
        initiator,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RetirementReceipt {
    pub pointer: u64,
    pub native_generation: u64,
    pub view_generation: u64,
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub base: u64,
    pub remaining_references: u64,
    pub provenance: MappingProvenance,
}

fn process_generation(generation: ProcessGeneration) -> (&'static [u8], u64) {
    match generation {
        ProcessGeneration::Hosted(value) => (b"hosted", value),
        ProcessGeneration::Temporary(value) => (b"temporary", value),
    }
}

fn view_identity(receipt: RetirementReceipt) {
    print_str(b"pointer="); print_hex_u64(receipt.pointer);
    print_str(b" native-generation="); print_u64(receipt.native_generation);
    print_str(b" view-generation="); print_u64(receipt.view_generation);
    print_str(b" provider-domain="); print_u64(receipt.provider_domain);
    print_str(b" provider-generation="); print_u64(receipt.provider_generation);
    print_str(b" base="); print_hex_u64(receipt.base);
    let provenance = receipt.provenance;
    print_str(b" section-index="); print_u64(provenance.section_index as u64);
    print_str(b" section-generation="); print_u64(provenance.section_generation);
    print_str(b" backing-kind="); print_u64(u64::from(provenance.backing_kind));
    print_str(b" file-present="); print_u64(u64::from(provenance.file.is_some()));
    if let Some(file) = provenance.file {
        print_str(b" file-mount="); print_u64(file.mount.value());
        print_str(b" file-id="); print_u64(file.file_id);
    }
    print_str(b" initiator=");
    if let Some(initiator) = provenance.initiator {
        let (kind, generation) = process_generation(initiator.process.generation);
        print_str(kind);
        print_str(b" initiator-pi="); print_u64(initiator.pi as u64);
        print_str(b" initiator-pid="); print_u64(u64::from(initiator.process.pid));
        print_str(b" initiator-generation="); print_u64(generation);
        print_str(b" initiator-tid="); print_u64(u64::from(initiator.thread.thread_id()));
        print_str(b" initiator-thread-generation="); print_u64(initiator.thread.generation());
    } else {
        print_str(b"unavailable");
    }
}

pub(crate) fn map_published(receipt: Option<RetirementReceipt>, size: u64, pages: u64) {
    let Some(receipt) = receipt else { return; };
    print_str(b"[kernel-section-map] "); view_identity(receipt);
    print_str(b" bytes="); print_u64(size);
    print_str(b" pages="); print_u64(pages); print_str(b"\n");
}

pub(crate) fn unmap_retired(receipt: Option<RetirementReceipt>) {
    let Some(receipt) = receipt else { return; };
    print_str(b"[kernel-section-unmap-retired] "); view_identity(receipt);
    print_str(b" remaining-refs="); print_u64(receipt.remaining_references);
    print_str(b"\n");
}

/// Called only after physical ingress authentication and the actual cleanup operation return.
/// A retained caller can be recorded after exit without manufacturing fresh handle authority.
pub(crate) unsafe fn observe_cleanup_result(
    handler: *const ExecNtHandler,
    channel: &spawn_hosts::PumpChannel,
    physical: runtime::PhysicalSource,
    op: u64,
    target: u64,
    result: &Result<u64, u32>,
    retired_view: Option<RetirementReceipt>,
) {
    let runtime::PhysicalDomain::Provider { domain, .. } = physical.domain else { return; };
    let name: &[u8] = match op {
        nt_io_manager::win32k_mm_section_wire::OP_UNMAP => b"unmap",
        nt_io_manager::win32k_mm_section_wire::OP_DEREFERENCE => b"dereference",
        _ => return,
    };
    let actor = match (channel.logical_caller, channel.kernel_caller) {
        (Some(caller), None) => {
            let current = (*handler).pm.validate_thread_lifetime(caller.thread())
                && (*handler).capture_process_identity(caller.pi()) == Some(caller.process());
            Some((b"logical" as &[u8], caller.thread(), current,
                Some((caller.pi(), caller.process()))))
        }
        (None, Some(caller)) => {
            let thread = caller.thread();
            let current = (*handler).pm.validate_thread_lifetime(thread)
                && (*handler).pm.process(thread.process_id()).is_some();
            let process = (0..MAX_PI).find_map(|pi| {
                let process = (*handler).capture_process_identity(pi)?;
                (process.pid == thread.process_id()).then_some((pi, process))
            });
            Some((b"kernel" as &[u8], thread, current, process))
        }
        _ => None,
    };
    print_str(b"[kernel-section-cleanup-result] op="); print_str(name);
    print_str(b" target="); print_hex_u64(target);
    print_str(b" provider-domain="); print_u64(domain.domain);
    print_str(b" provider-generation="); print_u64(domain.generation);
    print_str(b" caller=");
    if let Some((kind, thread, current, process)) = actor {
        print_str(kind);
        print_str(b" pid="); print_u64(thread.process_id() as u64);
        print_str(b" tid="); print_u64(u64::from(thread.thread_id()));
        print_str(b" thread-generation="); print_u64(thread.generation());
        print_str(b" process=");
        if let Some((pi, process)) = process {
            let (kind, generation) = process_generation(process.generation);
            print_str(kind);
            print_str(b" process-pi="); print_u64(pi as u64);
            print_str(b" process-generation="); print_u64(generation);
        } else { print_str(b"unavailable"); }
        print_str(b" canonical-current="); print_u64(u64::from(current));
        print_str(b" process-signaled=");
        if current {
            print_u64(u64::from((*handler).pm.is_process_signaled(thread.process_id())));
        } else { print_str(b"unknown"); }
    } else {
        print_str(b"none canonical-current=0 process-signaled=unknown");
    }
    match result {
        Ok(value) => {
            print_str(b" status="); print_hex(0);
            print_str(b" return-value="); print_u64(*value);
        }
        Err(status) => { print_str(b" status="); print_hex(*status); }
    }
    if result.is_ok() {
        if let Some(receipt) = retired_view {
            print_str(b" retired-view "); view_identity(receipt);
        }
    }
    print_str(b"\n");
}
