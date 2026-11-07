#[path = "../../../components/ntos-executive/src/scsi_srb_pump_phase.rs"]
mod scsi_srb_pump_phase;

use scsi_srb_pump_phase::ScsiSrbPumpPhase;

#[test]
fn admitted_dispatch_records_each_exclusive_phase_once() {
    let mut phase = ScsiSrbPumpPhase::new(100);
    assert_eq!(phase.finish(101), None);
    assert_eq!(phase.exit(102), None);
    assert_eq!(phase.enter(110), Some(10));
    assert_eq!(phase.enter(111), None);
    assert_eq!(phase.exit(140), Some(30));
    assert_eq!(phase.exit(141), None);
    assert_eq!(phase.finish(150), Some(10));
}

#[test]
fn elapsed_ticks_follow_the_existing_wrapping_clock_contract() {
    let mut phase = ScsiSrbPumpPhase::new(u64::MAX - 4);
    assert_eq!(phase.enter(2), Some(7));
    assert_eq!(phase.exit(9), Some(7));
    assert_eq!(phase.finish(20), Some(11));
}
