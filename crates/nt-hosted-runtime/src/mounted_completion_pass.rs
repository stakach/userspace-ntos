//! Order mounted-sector service around the hosted I/O completion pump.

/// Return native and I/O progress from one outer owner turn. The initial service
/// pass may settle a terminal already visible before the I/O Manager pump. If
/// the pump progresses while a physical owner remains, allow one more service
/// pass to observe its newly published completion without waiting for a timer.
/// The service callback alone authenticates and acknowledges that completion.
pub fn service_mounted_around_io_pump<Service, Pump, Pending>(
    mut service: Service,
    pump: Pump,
    pending: Pending,
) -> (u64, u64)
where
    Service: FnMut() -> u64,
    Pump: FnOnce() -> usize,
    Pending: FnOnce() -> bool,
{
    let native = service();
    let pumped = pump() as u64;
    let follow_on = if pumped != 0 && pending() { service() } else { 0 };
    (native.saturating_add(follow_on), pumped)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::service_mounted_around_io_pump;
    use self::std::cell::RefCell;
    use self::std::vec::Vec;

    #[derive(Default)]
    struct PhysicalOwner {
        pending: Option<u64>,
        completion: Option<u64>,
        queued: Option<u64>,
        settled: Vec<u64>,
        service_calls: usize,
    }

    fn service(owner: &RefCell<PhysicalOwner>) -> u64 {
        let mut owner = owner.borrow_mut();
        owner.service_calls += 1;
        if owner.pending != owner.completion || owner.pending.is_none() {
            return 0;
        }
        let exact = owner.pending.take().unwrap();
        owner.completion = None;
        owner.settled.push(exact);
        owner.pending = owner.queued.take();
        1
    }

    #[test]
    fn newly_published_exact_terminal_settles_and_admits_next_claim_in_same_turn() {
        let owner = RefCell::new(PhysicalOwner {
            pending: Some(7), queued: Some(8), ..PhysicalOwner::default()
        });
        let (native, pumped) = service_mounted_around_io_pump(
            || service(&owner),
            || { owner.borrow_mut().completion = Some(7); 1 },
            || owner.borrow().pending.is_some(),
        );
        let owner = owner.into_inner();
        assert_eq!((native, pumped), (1, 1));
        assert_eq!(owner.settled, [7]);
        assert_eq!(owner.pending, Some(8));
        assert_eq!(owner.service_calls, 2, "at most one follow-on native pass");
    }

    #[test]
    fn foreign_terminal_does_not_settle_the_retained_owner() {
        let owner = RefCell::new(PhysicalOwner { pending: Some(7), ..PhysicalOwner::default() });
        let (native, pumped) = service_mounted_around_io_pump(
            || service(&owner),
            || { owner.borrow_mut().completion = Some(99); 1 },
            || owner.borrow().pending.is_some(),
        );
        let owner = owner.into_inner();
        assert_eq!((native, pumped), (0, 1));
        assert_eq!(owner.pending, Some(7));
        assert_eq!(owner.completion, Some(99));
        assert!(owner.settled.is_empty());
        assert_eq!(owner.service_calls, 2, "foreign progress permits only one exact probe");
    }

    #[test]
    fn no_pump_progress_does_not_repeat_native_service() {
        let owner = RefCell::new(PhysicalOwner { pending: Some(7), ..PhysicalOwner::default() });
        let (native, pumped) = service_mounted_around_io_pump(
            || service(&owner),
            || 0,
            || owner.borrow().pending.is_some(),
        );
        assert_eq!((native, pumped), (0, 0));
        assert_eq!(owner.borrow().service_calls, 1);
    }

    #[test]
    fn unrelated_pump_progress_without_physical_owner_does_not_repeat_service() {
        let owner = RefCell::new(PhysicalOwner::default());
        let (native, pumped) = service_mounted_around_io_pump(
            || service(&owner),
            || 1,
            || owner.borrow().pending.is_some(),
        );
        assert_eq!((native, pumped), (0, 1));
        assert_eq!(owner.borrow().service_calls, 1);
    }
}
