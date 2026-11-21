//! Exercise the actual pending-File completion scan policy with a modelled provider.
use std::cell::{Cell, RefCell};

#[path = "../../../components/ntos-executive/src/pending_file_completion_scan.rs"]
mod scan;

/// Provider memory (`ready`) and the I/O Manager's published completions (`published`).
#[derive(Default)]
struct Model {
    ready: RefCell<Vec<u64>>,
    published: RefCell<Vec<u64>>,
    pumps: Cell<usize>,
}

impl Model {
    fn pump(&self) -> usize {
        self.pumps.set(self.pumps.get() + 1);
        let ready: Vec<u64> = self.ready.borrow_mut().drain(..).collect();
        self.published.borrow_mut().extend(&ready);
        ready.len()
    }
    fn published(&self, irp: u64) -> Option<u64> {
        self.published.borrow().contains(&irp).then_some(irp)
    }
}

/// One pass over `rows`; returns the rows delivered and whether the pass must be redriven.
fn pass(model: &Model, rows: &[u64], during: impl Fn(u64)) -> (Vec<u64>, bool) {
    let mut completions = scan::CompletionScan::begin(|| model.pump());
    let mut delivered = Vec::new();
    for &irp in rows {
        if let Some(irp) = completions.lookup(|| model.published(irp)) {
            delivered.push(irp);
            during(irp);
        } else {
            let _ = completions.copy_requires_retry(|| false);
        }
    }
    (delivered, completions.finish())
}

#[test]
fn an_idle_pass_polls_providers_a_fixed_number_of_times() {
    // Forty long-pending rows (pipe listens, input reads) with nothing complete.
    let model = Model::default();
    let rows: Vec<u64> = (1..=40).collect();
    let (delivered, redrive) = pass(&model, &rows, |_| {});
    assert!(delivered.is_empty());
    assert!(!redrive, "nothing became ready, so nothing is owed");
    assert!(model.pumps.get() <= 2, "{} pumps for an idle pass of 40 rows", model.pumps.get());
}

#[test]
fn a_row_is_driven_once_its_completion_is_ready() {
    let model = Model::default();
    model.ready.borrow_mut().push(7);
    let (delivered, redrive) = pass(&model, &[3, 7, 9], |_| {});
    assert_eq!(delivered, [7]);
    assert!(!redrive);
}

#[test]
fn a_completion_published_after_its_row_was_visited_redrives_the_pass() {
    // Delivering row 9 runs nested work that completes row 3, already visited this pass.
    let model = Model::default();
    model.ready.borrow_mut().push(9);
    let (delivered, redrive) = pass(&model, &[3, 9], |irp| {
        if irp == 9 { model.ready.borrow_mut().push(3); }
    });
    assert_eq!(delivered, [9]);
    assert!(redrive, "row 3's completion must not wait for an unrelated wake");
    let (delivered, _) = pass(&model, &[3], |_| {});
    assert_eq!(delivered, [3], "the redriven pass delivers it");
}
