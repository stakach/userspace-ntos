//! The per-major marshalling of a cross-domain IRP forward, independent of its transport.
//!
//! A forward captures one exact source IRP owned by an authenticated driver instance, builds
//! the canonical request its target device dispatches, and publishes the target's terminal
//! back into the source IRP. The primary forward protocols reach a projection from the source
//! driver's pump channel; an IRQ lane reaches the same projection from its lane instance. How
//! the target dispatch runs and how the source learns its disposition is the transport's work.

use super::*;
use nt_io_manager::detached_file_irp::{ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest};

/// The authenticated driver instance whose source IRP is forwarded.
#[derive(Clone, Copy)]
pub(super) struct ForwardSource {
    index: usize,
    inst: DriverInstance,
    domain: nt_io_manager::HostedDomainIdentity,
}

impl ForwardSource {
    /// An instance already authenticated by its transport (pump channel or IRQ lane).
    pub(super) fn new(index: usize, inst: DriverInstance) -> Option<Self> {
        let domain = instance_domain_identity(inst)?;
        Some(Self { index, inst, domain })
    }

    /// The driver instance that owns this primary pump channel.
    pub(super) unsafe fn for_pump_channel(
        ch: &crate::spawn_hosts::PumpChannel,
        reply_cap: u64,
    ) -> Option<Self> {
        let (index, inst) = instance_for_pump_channel(ch, reply_cap)?;
        Self::new(index, inst)
    }

    pub(super) fn index(self) -> usize { self.index }
    pub(super) fn instance(self) -> DriverInstance { self.inst }
    pub(super) fn domain(self) -> nt_io_manager::HostedDomainIdentity { self.domain }
}

/// The provider instance that dispatches a canonical device: the device's registered owner,
/// or the provider its owner routes dispatch through.
pub(super) unsafe fn target_provider(
    device_id: nt_io_manager::DeviceId,
) -> Option<(usize, DriverInstance)> {
    let (target_index, _, _) = hosted_driver_device_route_by_device_id(device_id.raw())?;
    let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
        .map_or(target_index, |route| route.provider_instance);
    instance(provider_index).map(|provider| (provider_index, provider))
}

/// The provider still dispatching `device_id` is exactly the one a forward captured.
pub(super) unsafe fn target_provider_is(
    device_id: nt_io_manager::DeviceId,
    captured: DriverInstance,
) -> Option<usize> {
    let (index, live) = target_provider(device_id)?;
    (live.pml4 == captured.pml4
        && live.exec_pool_va == captured.exec_pool_va
        && live.hosted_domain_id == captured.hosted_domain_id
        && live.hosted_domain_cookie == captured.hosted_domain_cookie
        && live.driver_id == captured.driver_id)
        .then_some(index)
}

/// The canonical request a projection asks its target device to dispatch.
pub(super) struct ForwardRequest<'a> {
    pub(super) request: ExternalFileIrpRequest,
    /// Source input copied into the target request.
    pub(super) input: &'a [u8],
    /// Bytes of zeroed output the target request owns.
    pub(super) output_length: usize,
    pub(super) policy: ExternalFileIrpDispatchPolicy,
}

impl ForwardRequest<'_> {
    /// Dispatch through the target provider's primary pump.
    pub(super) fn dispatch_primary(
        self,
        caller: nt_process::native_handle::NativeHandleCaller,
    ) -> Result<hosted_file_owners::PlainDispatch, nt_status::NtStatus> {
        let mut output = Vec::new();
        if output.try_reserve_exact(self.output_length).is_err() {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        output.resize(self.output_length, 0);
        hosted_file_owners::dispatch(caller, self.request, self.input, &output, self.policy)
    }
}

/// One IRP major's cross-domain marshalling.
pub(super) trait ForwardProjection: Sized {
    /// The IRP major this projection marshals.
    const MAJOR: u8;
    type Error: Copy;
    /// Target-domain input that exists only once the provider is chosen (QUERY_PATH's
    /// materialized security graph); `()` when the source capture alone determines the request.
    type TargetInput: ?Sized;

    /// Pin the exact source IRP owned by `source`, require its next stack location to name
    /// `target_device`, and own its parameters, buffers, File and target registration.
    unsafe fn capture(
        source: ForwardSource,
        source_irp: u64,
        target_device: u64,
    ) -> Result<Self, Self::Error>;

    /// The status the source observes for a refused capture or publication.
    fn refusal_status(error: Self::Error) -> i32;

    /// The canonical request the target device dispatches for this source IRP.
    fn target_request<'a>(
        &'a self,
        input: &'a Self::TargetInput,
        requestor_tid: u64,
    ) -> ForwardRequest<'a>;

    /// Write the target's terminal (its output, then IoStatus) into the live source IRP and
    /// admit the source completion's deferred free. A refused output publishes the refusal.
    unsafe fn publish(&self, status: u32, information: u64, output: &[u8])
        -> Result<(), Self::Error>;
}

/// Write IoStatus into the live source IRP at `irp` (an executive address).
pub(super) unsafe fn write_source_io_status(irp: u64, status: u32, information: u64) {
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut u32, status);
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64, information);
}
