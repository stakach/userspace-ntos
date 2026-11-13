//! The nesting shapes that today share root's one stack, replayed on run-token executors.

use super::tests::{wait, Root, Routes};
use super::*;
use ExecutorResume::{RouteRetired, Routed, Unrouted};
use ExecutorYield::{Done, Idle, Parked};

/// Executor A blocks on a driver while executor B serves a queued callback that itself blocks.
fn parked_parent_and_callback(root: &mut Root, driver: ExecutorWait, callback: ExecutorWait) -> (ExecutorHandle, ExecutorHandle) {
    let a = root.turn(Unrouted, Parked(driver));
    let b = root.turn(Unrouted, Parked(callback));
    assert_ne!(a, b);
    assert_eq!(root.state(a), ExecutorState::Parked(driver));
    assert_eq!(root.state(b), ExecutorState::Parked(callback));
    (a, b)
}

#[test]
fn queued_callback_turn_parks_its_own_executor_and_completes_lifo() {
    let mut routes = Routes::new();
    let (driver, callback) = (wait(routes.route(), 11), wait(routes.route(), 12));
    let mut root = Root::new(2, 2);
    let (a, b) = parked_parent_and_callback(&mut root, driver, callback);

    // The callback's provider answers first: only B runs, A keeps its exact wait.
    let run = root.resume(Routed(callback));
    assert_eq!(run.executor(), b);
    assert_eq!(root.state(a), ExecutorState::Parked(driver));
    root.yields(run, Idle);

    assert_eq!(root.turn(Routed(driver), Idle), a);
    assert_eq!(root.states(), [Ok(ExecutorState::Idle), Ok(ExecutorState::Idle)]);
}

#[test]
fn older_executor_completes_while_the_newer_callback_is_still_parked() {
    let mut routes = Routes::new();
    let (driver, callback) = (wait(routes.route(), 11), wait(routes.route(), 12));
    let mut root = Root::new(2, 2);
    let (a, b) = parked_parent_and_callback(&mut root, driver, callback);

    // Non-LIFO: one shared stack could not return to A underneath B's frames.
    assert_eq!(root.turn(Routed(driver), Idle), a);
    assert_eq!(root.state(b), ExecutorState::Parked(callback));

    // A is at loop-top again and takes unrelated work while B is still blocked.
    assert_eq!(root.turn(Unrouted, Idle), a);
    assert_eq!(root.turn(Routed(callback), Idle), b);
}

#[test]
fn three_parked_executors_complete_in_an_interleaved_order() {
    let mut routes = Routes::new();
    let waits = [wait(routes.route(), 1), wait(routes.route(), 2), wait(routes.route(), 3)];
    let mut root = Root::new(3, 3);
    let executors = waits.map(|wait| root.turn(Unrouted, Parked(wait)));

    for index in [1, 0, 2] {
        assert_eq!(root.turn(Routed(waits[index]), Idle), executors[index]);
    }
    assert!(root.states().iter().all(|state| *state == Ok(ExecutorState::Idle)));
}

#[test]
fn callback_executor_parks_again_for_each_nested_provider_call() {
    let mut routes = Routes::new();
    let (driver, callback, child) =
        (wait(routes.route(), 11), wait(routes.route(), 12), wait(routes.route(), 13));
    let mut root = Root::new(2, 2);
    let (a, b) = parked_parent_and_callback(&mut root, driver, callback);

    // The callback provider calls an export; serving it needs a third provider, so B parks on
    // that child with its callback frames still on its own stack.
    assert_eq!(root.turn(Routed(callback), Parked(child)), b);
    assert_eq!(root.refused(Routed(callback)), ExecutorError::NotParked);
    assert_eq!(root.state(a), ExecutorState::Parked(driver));

    // Child done: B answers the export and waits for the callback provider again.
    assert_eq!(root.turn(Routed(child), Parked(callback)), b);
    assert_eq!(root.refused(Routed(child)), ExecutorError::NotParked);
    assert_eq!(root.turn(Routed(callback), Idle), b);
    assert_eq!(root.turn(Routed(driver), Idle), a);
}

#[test]
fn add_device_turn_stays_parked_across_timer_and_irq_arrivals() {
    let mut routes = Routes::new();
    let (add_device, connect) = (wait(routes.route(), 21), wait(routes.route(), 22));
    let mut root = Root::new(2, 2);
    let turn = root.turn(Unrouted, Parked(add_device));

    // Timer and IRQ work goes to the executor at loop-top; the parked turn is never re-entered.
    for _ in 0..3 {
        let servant = root.turn(Unrouted, Idle);
        assert_ne!(servant, turn);
        assert_eq!(root.state(turn), ExecutorState::Parked(add_device));
    }

    // The driver's AddDevice calls back for a nested CONNECT child; the turn parks on the child.
    assert_eq!(root.turn(Routed(add_device), Parked(connect)), turn);
    assert_ne!(root.turn(Unrouted, Idle), turn);
    assert_eq!(root.state(turn), ExecutorState::Parked(connect));

    assert_eq!(root.turn(Routed(connect), Parked(add_device)), turn);
    assert_eq!(root.turn(Routed(add_device), Idle), turn);
}

#[test]
fn timer_arrival_with_every_executor_parked_is_exhaustion_until_one_returns() {
    let mut routes = Routes::new();
    let (driver, callback) = (wait(routes.route(), 11), wait(routes.route(), 12));
    let mut root = Root::new(2, 2);
    let (a, b) = parked_parent_and_callback(&mut root, driver, callback);

    // Neither a new executor nor a parked one is available: the arrival stays retained.
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
    assert_eq!(root.register(), Err(ExecutorError::NoCapacity));
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
    assert_eq!(root.state(a), ExecutorState::Parked(driver));
    assert_eq!(root.state(b), ExecutorState::Parked(callback));

    // Routed completions still run, and the retained timer arrival is then delivered.
    assert_eq!(root.turn(Routed(callback), Idle), b);
    assert_eq!(root.turn(Unrouted, Idle), b);
    assert_eq!(root.state(a), ExecutorState::Parked(driver));
}

#[test]
fn a_finished_turn_executor_frees_its_slot_for_the_next_turn() {
    let mut routes = Routes::new();
    let (driver, first_turn, second_turn) =
        (wait(routes.route(), 11), wait(routes.route(), 31), wait(routes.route(), 32));
    let mut root = Root::new(2, 2);
    let (a, b) = parked_parent_and_callback(&mut root, driver, first_turn);

    assert_eq!(root.turn(Routed(first_turn), Done), b);
    assert_eq!(root.refused(Unrouted), ExecutorError::NoIdleExecutor);
    let next = root.register().unwrap();
    assert_eq!(next.index(), b.index());
    assert_eq!(root.turn(Unrouted, Parked(second_turn)), next);

    // The first turn's late completion names its retired job, not the slot's new occupant.
    assert_eq!(root.refused(Routed(first_turn)), ExecutorError::NotParked);
    assert_eq!(root.turn(Routed(second_turn), Idle), next);
    assert_eq!(root.turn(Routed(driver), Idle), a);
}

#[test]
fn retiring_a_parked_executors_route_unwinds_only_that_executor() {
    let mut routes = Routes::new();
    let (driver, callback, cleanup) =
        (wait(routes.route(), 11), wait(routes.route(), 12), wait(routes.route(), 13));
    let mut root = Root::new(2, 2);
    let (a, b) = parked_parent_and_callback(&mut root, driver, callback);

    // The driver's route retires underneath A. A is told so on its own stack and may still
    // block while unwinding; B is untouched.
    let run = root.resume(RouteRetired(driver.route()));
    assert_eq!(run.executor(), a);
    assert_eq!(root.state(b), ExecutorState::Parked(callback));
    root.yields(run, Parked(cleanup));

    // Anything still queued for the retired route finds no waiter and wakes nobody.
    assert_eq!(root.refused(Routed(driver)), ExecutorError::NotParked);
    assert_eq!(root.refused(RouteRetired(driver.route())), ExecutorError::NotParked);

    assert_eq!(root.turn(Routed(cleanup), Idle), a);
    assert_eq!(root.turn(Routed(callback), Idle), b);
}

#[test]
fn retiring_a_route_with_no_waiter_wakes_nobody() {
    let mut routes = Routes::new();
    let (driver, unwaited) = (wait(routes.route(), 11), routes.route());
    let mut root = Root::new(2, 2);
    let a = root.turn(Unrouted, Parked(driver));

    assert_eq!(root.refused(RouteRetired(unwaited)), ExecutorError::NotParked);
    assert_eq!(root.state(a), ExecutorState::Parked(driver));
    assert_eq!(root.state(root.executors[1]), ExecutorState::Idle);
}
