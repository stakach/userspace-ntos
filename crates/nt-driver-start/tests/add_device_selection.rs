use nt_driver_start::{
    select_add_device_row, AddDeviceReadiness, AddDeviceSelection, AddDeviceSelectionEvidence,
    AwaitingBusPdo, PendingOperationTable,
};

use AddDeviceReadiness::{AwaitingBusPdo as Awaiting, NotReady, Ready};

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

/// A persisted bus child whose driver row was launched before its bus driver's row. `reported`
/// is whether the bus driver has reported the child's PDO yet.
fn bus_child(reported: bool) -> AddDeviceReadiness {
    AddDeviceReadiness::for_unentered_devnode(true, reported)
}

#[test]
fn a_devnode_that_needs_no_bus_pdo_is_ready() {
    assert_eq!(AddDeviceReadiness::for_unentered_devnode(false, false), Ready);
}

#[test]
fn a_bus_child_awaits_its_pdo_until_the_bus_reports_it() {
    assert_eq!(bus_child(false), Awaiting);
    assert_eq!(bus_child(true), Ready);
}

#[test]
fn a_child_awaiting_its_bus_pdo_yields_to_the_ready_bus_driver() {
    assert_eq!(
        select_add_device_row([("child", bus_child(false)), ("bus", Ready)]),
        AddDeviceSelection::Selected {
            owner: "bus",
            passed_over: Some(AwaitingBusPdo {
                first: "child",
                rows: 1
            }),
        }
    );
}

#[test]
fn the_child_is_admitted_once_its_bus_pdo_is_reported() {
    // The bus row has entered native START and its relations reported the child.
    assert_eq!(
        select_add_device_row([("child", bus_child(true)), ("bus", NotReady)]),
        selected("child")
    );
}

#[test]
fn several_awaiting_children_do_not_starve_a_ready_row() {
    assert_eq!(
        select_add_device_row([
            ("child-a", bus_child(false)),
            ("ordered", NotReady),
            ("child-b", bus_child(false)),
            ("child-c", bus_child(false)),
            ("ready", Ready),
            ("later", Ready),
        ]),
        AddDeviceSelection::Selected {
            owner: "ready",
            passed_over: Some(AwaitingBusPdo {
                first: "child-a",
                rows: 3
            }),
        }
    );
}

#[test]
fn only_awaiting_rows_is_an_explicit_wait_for_bus_relations() {
    // Nothing may be admitted. The caller must stop instead of retrying the head row, and the
    // result names what the batch waits for, including a child whose bus never reports it.
    assert_eq!(
        select_add_device_row([
            ("busy-bus", NotReady),
            ("child-a", bus_child(false)),
            ("child-b", bus_child(false)),
        ]),
        AddDeviceSelection::AwaitingBusRelations(AwaitingBusPdo {
            first: "child-a",
            rows: 2
        })
    );
}

fn awaiting_bus_relations(first: &'static str) -> AddDeviceSelection<&'static str> {
    AddDeviceSelection::AwaitingBusRelations(AwaitingBusPdo { first, rows: 1 })
}

fn selected_past(owner: &'static str, first: &'static str) -> AddDeviceSelection<&'static str> {
    AddDeviceSelection::Selected {
        owner,
        passed_over: Some(AwaitingBusPdo { first, rows: 1 }),
    }
}

#[test]
fn evidence_ignores_selections_with_no_awaiting_row() {
    let mut evidence = AddDeviceSelectionEvidence::new(8);
    assert!(!evidence.report(selected("bus")));
    assert!(!evidence.report(AddDeviceSelection::Idle));
}

#[test]
fn evidence_reports_each_distinct_awaiting_selection_once() {
    let mut evidence = AddDeviceSelectionEvidence::new(8);
    assert!(evidence.report(selected_past("bus", "child")));
    // The same row is selected again on a later turn, with ordinary turns in between.
    assert!(!evidence.report(selected_past("bus", "child")));
    assert!(!evidence.report(AddDeviceSelection::Idle));
    assert!(!evidence.report(selected_past("bus", "child")));
    assert!(evidence.report(awaiting_bus_relations("child")));
    assert!(!evidence.report(awaiting_bus_relations("child")));
    assert!(evidence.report(selected_past("display", "child")));
}

#[test]
fn evidence_is_bounded() {
    let mut evidence = AddDeviceSelectionEvidence::new(2);
    assert!(evidence.report(selected_past("bus", "child")));
    assert!(evidence.report(awaiting_bus_relations("child")));
    assert!(!evidence.report(selected_past("display", "child")));
    assert!(!evidence.report(awaiting_bus_relations("other")));
}
