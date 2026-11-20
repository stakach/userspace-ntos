//! x86 PC speaker programming for `HalMakeBeep`, following ReactOS hal/halx86/generic/beep.c.
//!
//! The speaker is gated by system control port B and driven by PIT channel 2 in square-wave
//! mode. Every call first disconnects the speaker. A nonzero frequency whose divider fits the
//! 16-bit PIT reload (0x10000 encodes as 0) reprograms channel 2 and reconnects it. Only that
//! case returns `true`; frequency zero silences the speaker and returns `false`, as on NT.
//! Channel 0 and channel 1 programming is never touched.

pub const PIT_FREQUENCY: u32 = 1_193_182;
pub const SYSTEM_CONTROL_PORT_B: u16 = 0x61;
pub const TIMER_CHANNEL2_DATA_PORT: u16 = 0x42;
pub const TIMER_CONTROL_PORT: u16 = 0x43;
/// Port B bit 0 gates PIT channel 2; bit 1 enables speaker data.
pub const TIMER2_GATE_TO_SPEAKER: u8 = 1 << 0;
pub const SPEAKER_DATA_ENABLE: u8 = 1 << 1;
/// Channel 2, low-then-high access, mode 3 (square wave), binary counting.
pub const CHANNEL2_SQUARE_WAVE: u8 = (2 << 6) | (3 << 4) | (3 << 1);

/// The HAL-owned port operations the speaker sequence needs.
pub trait SpeakerPorts {
    type Error;
    fn read(&mut self, port: u16) -> Result<u8, Self::Error>;
    fn write(&mut self, port: u16, value: u8) -> Result<(), Self::Error>;
}

/// The PIT reload value for `frequency`, or `None` when the speaker cannot produce it.
pub fn divider(frequency: u32) -> Option<u32> {
    if frequency == 0 { return None; }
    let divider = PIT_FREQUENCY / frequency;
    (divider <= 0x1_0000).then_some(divider)
}

/// Perform `HalMakeBeep(frequency)`. Any port error stops the sequence immediately; the caller
/// must not report a beep whose programming was not observed to complete.
pub fn make_beep<P: SpeakerPorts>(ports: &mut P, frequency: u32) -> Result<bool, P::Error> {
    let control = ports.read(SYSTEM_CONTROL_PORT_B)?;
    ports.write(SYSTEM_CONTROL_PORT_B, control & !(SPEAKER_DATA_ENABLE | TIMER2_GATE_TO_SPEAKER))?;
    let Some(divider) = divider(frequency) else { return Ok(false) };
    ports.write(TIMER_CONTROL_PORT, CHANNEL2_SQUARE_WAVE)?;
    ports.write(TIMER_CHANNEL2_DATA_PORT, divider as u8)?;
    ports.write(TIMER_CHANNEL2_DATA_PORT, (divider >> 8) as u8)?;
    let control = ports.read(SYSTEM_CONTROL_PORT_B)?;
    ports.write(SYSTEM_CONTROL_PORT_B, control | SPEAKER_DATA_ENABLE | TIMER2_GATE_TO_SPEAKER)?;
    Ok(true)
}

#[cfg(test)]
#[path = "pc_speaker_tests.rs"]
mod tests;
