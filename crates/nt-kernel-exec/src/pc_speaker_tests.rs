extern crate std;

use super::*;
use std::vec::Vec;

#[derive(Default)]
struct Ports {
    port_b: u8,
    log: Vec<(char, u16, u8)>,
    fail_at: Option<usize>,
}

impl SpeakerPorts for Ports {
    type Error = usize;
    fn read(&mut self, port: u16) -> Result<u8, usize> {
        if self.fail_at == Some(self.log.len()) { return Err(self.log.len()); }
        assert_eq!(port, SYSTEM_CONTROL_PORT_B);
        self.log.push(('r', port, self.port_b));
        Ok(self.port_b)
    }
    fn write(&mut self, port: u16, value: u8) -> Result<(), usize> {
        if self.fail_at == Some(self.log.len()) { return Err(self.log.len()); }
        if port == SYSTEM_CONTROL_PORT_B { self.port_b = value; }
        self.log.push(('w', port, value));
        Ok(())
    }
}

#[test]
fn audible_frequency_programs_channel_two_square_wave_and_connects_speaker() {
    // Unrelated port B bits (for example the NMI and parity controls) are preserved.
    let mut ports = Ports { port_b: 0xf0 | TIMER2_GATE_TO_SPEAKER, ..Ports::default() };
    assert_eq!(make_beep(&mut ports, 1000), Ok(true));
    let divider = PIT_FREQUENCY / 1000;
    assert_eq!(ports.log, [
        ('r', 0x61, 0xf1),
        ('w', 0x61, 0xf0),
        ('w', 0x43, 0xb6),
        ('w', 0x42, divider as u8),
        ('w', 0x42, (divider >> 8) as u8),
        ('r', 0x61, 0xf0),
        ('w', 0x61, 0xf3),
    ]);
}

#[test]
fn zero_frequency_only_silences_and_reports_false() {
    let mut ports = Ports { port_b: 0x03, ..Ports::default() };
    assert_eq!(make_beep(&mut ports, 0), Ok(false));
    assert_eq!(ports.log, [('r', 0x61, 0x03), ('w', 0x61, 0x00)]);
}

#[test]
fn inaudible_low_frequency_silences_without_touching_the_pit() {
    assert_eq!(divider(18), None);
    assert_eq!(divider(19), Some(PIT_FREQUENCY / 19));
    let mut ports = Ports { port_b: 0x03, ..Ports::default() };
    assert_eq!(make_beep(&mut ports, 18), Ok(false));
    assert!(ports.log.iter().all(|(_, port, _)| *port == SYSTEM_CONTROL_PORT_B));
}

#[test]
fn port_failure_stops_the_sequence_without_reporting_a_beep() {
    let mut ports = Ports { fail_at: Some(3), ..Ports::default() };
    assert_eq!(make_beep(&mut ports, 440), Err(3));
    assert_eq!(ports.log.len(), 3);
    assert_eq!(ports.port_b & (SPEAKER_DATA_ENABLE | TIMER2_GATE_TO_SPEAKER), 0);
}
