use super::*;
use crate::process_identity::ProcessGeneration;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use nt_memory_manager::retained_alias::AliasRetirementIo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Unmap(u64),
    Map(u64, u64),
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    fail: Vec<Call>,
}

#[derive(Clone, Default)]
struct Io(Rc<RefCell<State>>);

impl Io {
    fn effect(&self, call: Call) -> Result<(), u32> {
        let mut state = self.0.borrow_mut();
        state.calls.push(call);
        if state.fail.contains(&call) {
            Err(99)
        } else {
            Ok(())
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.0.borrow().calls.clone()
    }

    fn clear(&self) {
        self.0.borrow_mut().calls.clear();
    }
}

impl AliasRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Call::Unmap(cap))
    }
    fn delete(&mut self, _: u64) -> Result<(), u32> {
        panic!("window switch must retain caps")
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("window switch must retain slots")
    }
    fn recycle_unretyped_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("window switch must retain slots")
    }
}

impl AliasTransitionIo for Io {
    fn copy(&mut self) -> (u64, u32) {
        panic!("window switch must reuse exact caps")
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.effect(Call::Map(cap, rights))
    }
}

struct Setup {
    io: Io,
    cap: u64,
}

impl AliasRetirementIo for Setup {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.io.unmap(cap)
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.io.delete(cap)
    }
    fn recycle_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.io.recycle_slot(cap)
    }
    fn recycle_unretyped_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.io.recycle_unretyped_slot(cap)
    }
}

impl AliasTransitionIo for Setup {
    fn copy(&mut self) -> (u64, u32) {
        (self.cap, 0)
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.io.map(cap, rights)
    }
}

fn owner() -> WindowOwner {
    WindowOwner {
        pi: 3,
        process: ProcessIdentity {
            pid: 8,
            generation: ProcessGeneration::Hosted(11),
        },
        vspace: 40,
    }
}

fn row(page: u64, cap: u64, rights: u64, io: &Io) -> ThreadAliasMapping {
    let mut row = ThreadAliasMapping::new(page).unwrap();
    row.replace(
        rights,
        &mut Setup {
            io: io.clone(),
            cap,
        },
    )
    .unwrap();
    row
}

fn rows(io: &Io) -> Vec<ThreadAliasMapping> {
    vec![row(0x1000, 11, 1, io), row(0x2000, 12, 3, io)]
}

#[test]
fn suspends_all_then_restores_same_caps_and_rights_in_reverse_order() {
    let io = Io::default();
    let mut rows = rows(&io);
    io.clear();
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    window
        .suspend_all(owner(), &mut rows, |_| io.clone())
        .unwrap();
    assert!(window.is_complete());
    assert_eq!(rows[0].suspended(), Some((11, 1)));
    assert_eq!(rows[1].suspended(), Some((12, 3)));
    window
        .restore_all(owner(), &mut rows, |_| io.clone())
        .unwrap();
    assert_eq!(window.state(), WindowState::Active);
    assert_eq!(rows[0].live(), Some((11, 1)));
    assert_eq!(rows[1].live(), Some((12, 3)));
    assert_eq!(
        io.calls(),
        vec![
            Call::Unmap(11),
            Call::Unmap(12),
            Call::Map(12, 3),
            Call::Map(11, 1)
        ]
    );
}

#[test]
fn mid_suspend_failure_restores_prior_page_without_recopy() {
    let io = Io::default();
    let mut rows = rows(&io);
    io.clear();
    io.0.borrow_mut().fail.push(Call::Unmap(12));
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    assert_eq!(
        window.suspend_all(owner(), &mut rows, |_| io.clone()),
        Err(WindowError::Backend {
            page: 0x2000,
            status: 99
        })
    );
    assert_eq!(window.state(), WindowState::Active);
    assert_eq!(rows[0].live(), Some((11, 1)));
    assert_eq!(rows[1].live(), Some((12, 3)));
    assert_eq!(
        io.calls(),
        vec![Call::Unmap(11), Call::Unmap(12), Call::Map(11, 1)]
    );
}

#[test]
fn failed_rollback_blocks_new_transition_until_exact_retry() {
    let io = Io::default();
    let mut rows = rows(&io);
    io.clear();
    io.0.borrow_mut()
        .fail
        .extend([Call::Unmap(12), Call::Map(11, 1)]);
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    assert_eq!(
        window.suspend_all(owner(), &mut rows, |_| io.clone()),
        Err(WindowError::Backend {
            page: 0x2000,
            status: 99
        })
    );
    assert_eq!(window.state(), WindowState::Blocked);
    assert_eq!(rows[0].suspended(), Some((11, 1)));
    assert_eq!(
        window.suspend_all(owner(), &mut rows, |_| io.clone()),
        Err(WindowError::Busy)
    );
    io.0.borrow_mut().fail.clear();
    io.clear();
    window.recover(owner(), &mut rows, |_| io.clone()).unwrap();
    assert_eq!(io.calls(), vec![Call::Map(11, 1)]);
    assert_eq!(window.state(), WindowState::Active);
}

#[test]
fn failed_restore_retains_only_unmapped_pages_for_retry() {
    let io = Io::default();
    let mut rows = rows(&io);
    io.clear();
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    window
        .suspend_all(owner(), &mut rows, |_| io.clone())
        .unwrap();
    io.clear();
    io.0.borrow_mut().fail.push(Call::Map(12, 3));
    assert_eq!(
        window.restore_all(owner(), &mut rows, |_| io.clone()),
        Err(WindowError::Backend {
            page: 0x2000,
            status: 99
        })
    );
    assert_eq!(window.state(), WindowState::Blocked);
    assert_eq!(rows[0].live(), Some((11, 1)));
    assert_eq!(rows[1].suspended(), Some((12, 3)));
    io.0.borrow_mut().fail.clear();
    io.clear();
    window.recover(owner(), &mut rows, |_| io.clone()).unwrap();
    assert_eq!(io.calls(), vec![Call::Map(12, 3)]);
}

#[test]
fn changed_coverage_after_suspend_prevents_restore_effects() {
    let io = Io::default();
    let mut rows = rows(&io);
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    window
        .suspend_all(owner(), &mut rows, |_| io.clone())
        .unwrap();
    rows.push(ThreadAliasMapping::new(0x3000).unwrap());
    io.clear();
    assert_eq!(
        window.restore_all(owner(), &mut rows, |_| io.clone()),
        Err(WindowError::StaleMappings)
    );
    assert!(io.calls().is_empty());
    assert_eq!(window.state(), WindowState::Suspended);
}

#[test]
fn wrong_generation_pi_or_vspace_cannot_act_on_window() {
    let io = Io::default();
    let mut rows = rows(&io);
    io.clear();
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    for changed in [
        WindowOwner { pi: 4, ..owner() },
        WindowOwner {
            process: ProcessIdentity {
                generation: ProcessGeneration::Hosted(12),
                ..owner().process
            },
            ..owner()
        },
        WindowOwner {
            vspace: 41,
            ..owner()
        },
    ] {
        assert_eq!(
            window.suspend_all(changed, &mut rows, |_| io.clone()),
            Err(WindowError::OwnerChanged)
        );
    }
    assert!(io.calls().is_empty());
}

#[test]
fn duplicate_pages_caps_and_in_flight_rows_fail_before_unmap() {
    let io = Io::default();
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    let mut duplicate_page = vec![row(0x1000, 11, 1, &io), row(0x1000, 12, 1, &io)];
    io.clear();
    assert_eq!(
        window.suspend_all(owner(), &mut duplicate_page, |_| io.clone()),
        Err(WindowError::DuplicatePage(0x1000))
    );
    let mut duplicate_cap = vec![row(0x1000, 11, 1, &io), row(0x2000, 11, 1, &io)];
    io.clear();
    assert_eq!(
        window.suspend_all(owner(), &mut duplicate_cap, |_| io.clone()),
        Err(WindowError::SharedCapability(11))
    );
    let mut in_flight = vec![ThreadAliasMapping::new(0x1000).unwrap()];
    io.clear();
    assert_eq!(
        window.suspend_all(owner(), &mut in_flight, |_| io.clone()),
        Err(WindowError::StaleMappings)
    );
    assert!(io.calls().is_empty());
}

#[test]
fn retirement_claim_excludes_window_transition() {
    use crate::thread_alias_journal::ThreadAliasJournal;
    use crate::thread_resources::ThreadMemoryLayout;
    use crate::thread_rollback::{new_rollback_id, ThreadRollbackIdentity};
    let io = Io::default();
    let mut rows = rows(&io);
    let id = new_rollback_id(ThreadRollbackIdentity {
        pi: owner().pi,
        pid: owner().process.pid,
        process_generation: owner().process.generation,
        tid: 7,
    })
    .unwrap();
    let layout = ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x6000, 0xa000).unwrap();
    let journal = ThreadAliasJournal::prepare(id, layout, owner().pi as u64, &rows).unwrap();
    journal.claim(id, owner().pi as u64, &mut rows).unwrap();
    io.clear();
    let mut window = ClientAliasWindow::new(owner()).unwrap();
    assert_eq!(
        window.suspend_all(owner(), &mut rows, |_| io.clone()),
        Err(WindowError::Claimed)
    );
    assert!(io.calls().is_empty());
}
