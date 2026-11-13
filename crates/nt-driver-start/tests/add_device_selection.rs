use nt_driver_start::{
    select_add_device_row, AddDeviceReadiness, AddDeviceSelection, PendingOperationTable,
};

use AddDeviceReadiness::{NotReady, Ready};

fn selected<O>(owner: O) -> AddDeviceSelection<O> {
    AddDeviceSelection::Selected {
        owner,
        passed_over: None,
    }
}

#[test]
fn first_boot_admits_the_root_bus_before_the_root_display_row() {
    // The fresh-install shape: the ACPI root bus row and one ROOT-enumerated display row.
    let mut table = PendingOperationTable::with_capacity(2);
    let bus = table.reserve().unwrap();
    table.publish(bus, ()).unwrap();
    let display = table.reserve().unwrap();
    table.publish(display, ()).unwrap();

    assert_eq!(
        select_add_device_row([(bus, Ready), (display, Ready)]),
        selected(bus)
    );
    // The bus row has entered native AddDevice/START; the display row is next.
    assert_eq!(
        select_add_device_row([(bus, NotReady), (display, Ready)]),
        selected(display)
    );
}

#[test]
fn a_row_with_no_unentered_devnode_does_not_hide_a_later_ready_row() {
    // A row ordered behind a live predecessor, or already in native work, offers nothing.
    assert_eq!(
        select_add_device_row([("ordered", NotReady), ("busy", NotReady), ("ready", Ready)]),
        selected("ready")
    );
}

#[test]
fn table_order_decides_between_ready_rows() {
    assert_eq!(
        select_add_device_row([("start", Ready), ("rebalance", Ready)]),
        selected("start")
    );
}

#[test]
fn no_unentered_devnode_is_idle() {
    assert_eq!(
        select_add_device_row::<u8>([]),
        AddDeviceSelection::Idle
    );
    assert_eq!(
        select_add_device_row([(1u8, NotReady), (2, NotReady)]),
        AddDeviceSelection::Idle
    );
}

#[test]
fn rows_after_the_selected_one_are_not_inspected() {
    let mut inspected = 0;
    let rows = [(1u8, NotReady), (2, Ready), (3, Ready)]
        .into_iter()
        .inspect(|_| inspected += 1);
    assert_eq!(select_add_device_row(rows), selected(2));
    assert_eq!(inspected, 2);
}
