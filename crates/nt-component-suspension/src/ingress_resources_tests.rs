use super::*;
use alloc::vec;

#[test]
fn invalid_slot_sets_return_original_reply_ownership() {
    for (endpoint, replies) in [
        (0, vec![2, 3]),
        (1, vec![]),
        (1, vec![2]),
        (1, vec![2, 0]),
        (1, vec![2, 1]),
        (1, vec![2, 2]),
    ] {
        let expected = replies.clone();
        let (error, returned) = IngressResources::new(endpoint, replies).err().unwrap();
        assert_eq!(error, IngressResourceError::InvalidSlots);
        assert_eq!(returned, expected);
    }
}

#[test]
fn successful_creation_records_every_exact_resource_and_forbids_replay() {
    let mut owner = IngressResources::new(10, vec![20, 30, 40]).ok().unwrap();
    assert!(!owner.is_ready());
    assert_eq!(owner.endpoint(), 10);
    assert_eq!(owner.reply_slots().collect::<Vec<_>>(), vec![20, 30, 40]);
    let mut seen = Vec::new();
    owner
        .initialize(|kind, slot| {
            seen.push((kind, slot));
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(
        seen,
        vec![
            (IngressResourceKind::Endpoint, 10),
            (IngressResourceKind::Reply, 20),
            (IngressResourceKind::Reply, 30),
            (IngressResourceKind::Reply, 40)
        ]
    );
    assert!(owner.is_ready());
    assert!(owner
        .records()
        .iter()
        .all(|record| record.phase == IngressResourcePhase::Created));
    assert_eq!(
        owner.initialize(|_, _| -> Result<(), u8> { panic!("creation replay") }),
        Err(IngressResourceError::InvalidPhase)
    );
}

#[test]
fn failure_at_every_boundary_retains_created_entered_and_reserved_slots() {
    for fail in 0..4 {
        let mut owner = IngressResources::new(10, vec![20, 30, 40]).ok().unwrap();
        let mut calls = 0;
        assert_eq!(
            owner.initialize(|_, _| {
                let current = calls;
                calls += 1;
                if current == fail {
                    Err(9u8)
                } else {
                    Ok(())
                }
            }),
            Err(IngressResourceError::Invoke(9))
        );
        assert_eq!(calls, fail + 1);
        assert!(!owner.is_ready());
        for (index, record) in owner.records().iter().enumerate() {
            let expected = if index < fail {
                IngressResourcePhase::Created
            } else if index == fail {
                IngressResourcePhase::Creating
            } else {
                IngressResourcePhase::Reserved
            };
            assert_eq!(record.phase, expected);
        }
        assert_eq!(
            owner.initialize(|_, _| -> Result<(), u8> { panic!("uncertain creation replay") }),
            Err(IngressResourceError::InvalidPhase)
        );
        assert_eq!(owner.reply_slots().collect::<Vec<_>>(), vec![20, 30, 40]);
    }
}
