//! `HalMakeBeep`: the root HAL owns the PC speaker ports and programs them for an
//! authenticated hosted driver caller. A driver domain never receives these port caps.

use super::*;
use nt_kernel_exec::pc_speaker::{
    self, SpeakerPorts, SYSTEM_CONTROL_PORT_B, TIMER_CHANNEL2_DATA_PORT, TIMER_CONTROL_PORT,
};

pub(super) const LABEL: u64 = 0x7DA;
const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185u32 as i32;

/// `BOOLEAN HalMakeBeep(ULONG Frequency)`. A DPC or IRQ callback runs on the domain's IRQ lane,
/// whose root exchange admits only typed arena services, so it requests the same root program
/// through the lane instead of a primary-channel Call.
pub(super) extern "win64" fn make_beep(frequency: u32) -> u8 {
    if let Some((_, identity, _, _, grant)) = unsafe { hosted_irq_lane_context() } {
        let mut arguments = [0; nt_hosted_runtime::HOSTED_IRQ_ARENA_ARGUMENT_CAP];
        arguments[0] = u64::from(frequency);
        let result = unsafe { hosted_irq_lane_service(nt_hosted_runtime::HostedIrqServiceCommand {
            kind: nt_hosted_runtime::HostedIrqServiceKind::HalMakeBeep,
            service_id: LABEL,
            target_domain_id: identity.domain_id,
            target_domain_cookie: identity.domain_cookie,
            authority_cookie: 0,
            grant,
            argument_count: 1,
            arguments,
        }) };
        if result.faulted || result.value_count != 1 {
            hosted_irq_lane_protocol_fault(u64::from(frequency));
        }
        return u8::from(result.status == STATUS_SUCCESS && result.values[0] == 1);
    }
    let (label, status, beeping, _, _) =
        unsafe { call_on4((LABEL << 12) | 1, u64::from(frequency), 0, 0, 0) };
    if label != 0 { return 0; }
    u8::from(status as u32 as i32 == STATUS_SUCCESS && beeping == 1)
}

/// Root-owned port caps: PIT channel 2 data plus the control port, and system control port B.
/// Channel 0 belongs to the delay timer; a channel 2 control word cannot reprogram it.
static PIT_CHANNEL2_PORTS: AtomicU64 = AtomicU64::new(0);
static PORT_B: AtomicU64 = AtomicU64::new(0);
static SPEAKER_LOCK: AtomicBool = AtomicBool::new(false);

struct SpeakerGuard;
impl Drop for SpeakerGuard {
    fn drop(&mut self) { SPEAKER_LOCK.store(false, Ordering::Release); }
}

fn lock_speaker() -> SpeakerGuard {
    while SPEAKER_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        crate::yield_now();
    }
    SpeakerGuard
}

/// Issue the exact port window once. A failed issue leaves no cap and is retried next call.
unsafe fn port_cap(owner: &AtomicU64, first: u16, last: u16) -> Result<u64, i32> {
    let cap = owner.load(Ordering::Acquire);
    if cap != 0 { return Ok(cap); }
    let slot = crate::try_alloc_slot().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    if unsafe { crate::issue_ioport_cap(slot, first, last) } != 0 {
        crate::recycle_deleted_root_slot(slot);
        return Err(STATUS_DEVICE_NOT_READY);
    }
    owner.store(slot, Ordering::Release);
    Ok(slot)
}

struct RootSpeakerPorts { pit: u64, port_b: u64 }

impl RootSpeakerPorts {
    fn cap(&self, port: u16) -> Result<u64, u64> {
        match port {
            SYSTEM_CONTROL_PORT_B => Ok(self.port_b),
            TIMER_CHANNEL2_DATA_PORT | TIMER_CONTROL_PORT => Ok(self.pit),
            _ => Err(u64::MAX),
        }
    }
}

impl SpeakerPorts for RootSpeakerPorts {
    type Error = u64;
    fn read(&mut self, port: u16) -> Result<u8, u64> {
        let (value, error) = unsafe { crate::io_in8_r(self.cap(port)?, port) };
        if error == 0 { Ok(value) } else { Err(error) }
    }
    fn write(&mut self, port: u16, value: u8) -> Result<(), u64> {
        let error = unsafe { crate::io_out8(self.cap(port)?, port, value) };
        if error == 0 { Ok(()) } else { Err(error) }
    }
}

/// Returns `(status, beeping)`. A port fault is a device error, never a reported beep.
pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    frequency: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return (STATUS_ACCESS_DENIED, 0);
    }
    let Ok(frequency) = u32::try_from(frequency) else { return (STATUS_INVALID_PARAMETER, 0) };
    program(frequency)
}

/// Program the root-owned speaker for a caller its transport already authenticated.
pub(super) fn program(frequency: u32) -> (i32, u64) {
    let _guard = lock_speaker();
    let ports = unsafe {
        port_cap(&PIT_CHANNEL2_PORTS, TIMER_CHANNEL2_DATA_PORT, TIMER_CONTROL_PORT)
            .and_then(|pit| port_cap(&PORT_B, SYSTEM_CONTROL_PORT_B, SYSTEM_CONTROL_PORT_B)
                .map(|port_b| RootSpeakerPorts { pit, port_b }))
    };
    let mut ports = match ports {
        Ok(ports) => ports,
        Err(status) => return (status, 0),
    };
    match pc_speaker::make_beep(&mut ports, frequency) {
        Ok(beeping) => (STATUS_SUCCESS, u64::from(beeping)),
        Err(_) => (STATUS_IO_DEVICE_ERROR, 0),
    }
}
