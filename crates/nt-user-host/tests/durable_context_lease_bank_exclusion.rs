use nt_user_host::durable_context_lease::DurableContextLeases;

#[derive(Debug)]
struct Bank { primary: u64, secondary: Option<u64> }

#[test]
fn suspended_owner_still_excludes_both_physical_banks() {
    let mut leases = DurableContextLeases::<u64, Bank>::new();
    let reservation = leases.reserve().unwrap();
    let ticket = leases.retain(reservation, 17, Bank {
        primary: 0x1000, secondary: Some(0x2000),
    }).unwrap();
    leases.bind(ticket).unwrap();
    leases.unbind(ticket).unwrap();
    assert!(leases.any_held(|bank| bank.primary == 0x1000));
    assert!(leases.any_held(|bank| bank.secondary == Some(0x2000)));
    assert!(!leases.any_held(|bank| bank.primary == 0x3000));
    leases.retire(ticket).unwrap();
    assert!(!leases.any_held(|bank| bank.primary == 0x1000));
}
