#[path = "../../../components/ntos-executive/src/allocator_walk_observation.rs"]
mod observation;

use observation::WalkCounter;

#[test]
fn isolated_heap_does_not_touch_shared_image_counters() {
    let counter = WalkCounter::new();
    counter.record(false, 256, 9);
    let root_view = counter.sample(true);
    assert_eq!(root_view.operations, 0);
    assert_eq!(root_view.visited, 0);
    assert_eq!(root_view.max_visited, 0);
    assert_eq!(root_view.ticks, 0);

    counter.record(true, 0, 5);
    counter.record(true, 256, 70);
    counter.record(true, 128, 0);
    let root_view = counter.sample(true);
    assert_eq!(root_view.operations, 3);
    assert_eq!(root_view.visited, 384);
    assert_eq!(root_view.max_visited, 256);
    assert_eq!(root_view.ticks, 75);

    let isolated_view = counter.sample(false);
    assert_eq!(isolated_view.operations, 0);
    assert_eq!(isolated_view.visited, 0);
    assert_eq!(isolated_view.max_visited, 0);
    assert_eq!(isolated_view.ticks, 0);
}
