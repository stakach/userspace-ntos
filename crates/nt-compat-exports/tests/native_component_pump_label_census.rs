//! Exercise the actual component-pump label census arithmetic.
fn print_str(_: &[u8]) {}
fn disk_census_ticks() -> u64 { 0 }
fn root_dispatch_receive_ticks() -> u64 { 0 }
mod serial_records { pub fn is_root_executor() -> bool { true } }

#[allow(dead_code)] // The root glue is exercised only through the pump loop.
#[path = "../../../components/ntos-executive/src/component_pump_label_census.rs"]
mod census;

use census::{LabelCensus, LabelCost};

#[test]
fn a_cycle_splits_into_root_handling_and_blocked_time() {
    let mut labels = LabelCensus::new();
    labels.record(0x799, 1_000, 300);
    labels.record(0x799, 500, 600); // blocked never exceeds the cycle
    assert_eq!(labels.cost(0x799), LabelCost { cycles: 2, ticks: 1_500, blocked: 800 });
    // Labels from 0x900 up share one bucket.
    labels.record(0x900, 10, 0);
    labels.record(0x1234, 10, 0);
    assert_eq!(labels.cost(0xffff).cycles, 2);
}

#[test]
fn the_census_ranks_labels_by_root_handling() {
    let mut labels = LabelCensus::new();
    labels.record(3, 9_000_000, 1_000_000);     // 8 Mtick of handling
    labels.record(0x799, 20_000_000, 18_000_000); // 2 Mtick of handling
    labels.record(0x1000, 4_000_000, 0);
    let mut out = String::new();
    labels.write_census(&mut out).unwrap();
    assert_eq!(out, "[census] component-pump-label top label/cycles/handling-Mtick/blocked-Mtick: \
        0x3/1/8/1 other/1/4/0 0x799/1/2/18\n");
}
