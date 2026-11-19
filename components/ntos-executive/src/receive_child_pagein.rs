//! Root turns while an owned page-in holds the selected Receive child's Reply.
//!
//! The child's parent provider stays held, so the ordinary root maintenance, provider resume
//! and hosted delivery all remain excluded. A mounted routed READ completes through the native
//! block route: the storage provider's ISR and DPC publish the SCSI terminal, the native block
//! owner acknowledges it, and the mounted backend completes the File IRP. Each notification
//! runs exactly that chain and then the child's own page-in row; nothing else can reply, enter
//! the held provider or change the child's attachment.

use crate::*;

/// Deferral needs the ordinary root receive. An exclusive AddDevice, queued-callback or
/// registry-journal root owns its own timer and notification protocol instead.
pub(crate) unsafe fn deferral_admitted() -> bool {
    !service_sec_image::root_add_device_exclusive_pending()
        && !service_sec_image::root_queued_callback_exclusive_pending()
        && !driver_launch::unsettled_queued_callback()
        && !writable_fs::registry_journal::owns_volume()
}

/// One timer or IRQ notification while the child's page-in owns its Reply.
pub(crate) unsafe fn service_notification(
    handler: &mut ExecNtHandler,
    dispatcher: &NativeSyscallDispatcher,
    badge: u64,
) -> Result<(), nt_status::NtStatus> {
    let _message = ipc_message::SavedMessageBuffer::capture();
    let _ = driver_launch::latch_hosted_irq_badge(badge);
    let _ = driver_launch::drain_pending_hosted_irqs();
    let _ = driver_launch::drain_hosted_driver_dpcs();
    // The native block owner settles the exact SCSI terminal before its backend continues.
    let _ = driver_launch::service_mounted_native_blocks();
    let _ = driver_launch::service_pending_file_backends();
    if badge_has_delay_timer(badge) {
        ack_receive_child_pagein_timer()?;
    }
    native_image_pagein_work::redrive_receive_child(handler, dispatcher);
    Ok(())
}

/// Arm only the page-in, native block and DPC wakes before the root blocks. General timer
/// delivery can enter unrelated providers and waits for the held parent's settlement.
pub(crate) unsafe fn prepare_receive() -> bool {
    let pending = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::AcqRel);
    if pending != 0 {
        PUMP_TIMER_TICKS_DRAINED.fetch_add(pending, Ordering::Relaxed);
    }
    let now = monotonic_time_100ns();
    let Some(deadline) = [
        native_image_pagein_work::next_deadline(),
        driver_launch::mounted_native_block_next_deadline(now),
        driver_launch::hosted_dpc_next_deadline(now),
    ].into_iter().flatten().min() else {
        return false;
    };
    delay_timer_program(deadline, DELAY_TIMER_SOURCE_NATIVE_IMAGE_PAGEIN)
}
