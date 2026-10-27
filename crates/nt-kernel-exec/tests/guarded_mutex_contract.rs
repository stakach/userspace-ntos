//! The released classpnp driver imports the guarded-mutex ABI. A contended acquire must
//! retain its thread and wait ownership until the previous owner releases the mutex.

use nt_kernel_exec::executive_sync::{
    guarded_mutex_layout, kthread_layout, ExecutiveSyncError, GuardedMutexStore,
    GuardedMutexWaitAdmission,
};

#[repr(align(8))]
struct Aligned<const N: usize>([u8; N]);

fn special_apc_disable(thread: &Aligned<0x280>) -> i16 {
    i16::from_le_bytes(
        thread.0[kthread_layout::SPECIAL_APC_DISABLE
            ..kthread_layout::SPECIAL_APC_DISABLE + 2]
            .try_into()
            .unwrap(),
    )
}

fn count(mutex: &Aligned<0x40>) -> i32 {
    i32::from_le_bytes(
        mutex.0[guarded_mutex_layout::COUNT..guarded_mutex_layout::COUNT + 4]
            .try_into()
            .unwrap(),
    )
}

fn owner(mutex: &Aligned<0x40>) -> u64 {
    u64::from_le_bytes(
        mutex.0[guarded_mutex_layout::OWNER..guarded_mutex_layout::OWNER + 8]
            .try_into()
            .unwrap(),
    )
}

#[test]
fn contention_parks_second_thread_and_wakes_only_after_owner_release() {
    let mut mutex = Aligned([0xaau8; 0x40]);
    let mut first_thread = Aligned([0u8; 0x280]);
    let mut second_thread = Aligned([0u8; 0x280]);
    let mut store = GuardedMutexStore::new();
    let first = 0x1000;
    let second = 0x2000;
    let wake_cookie = 0xabc0;

    unsafe {
        store.initialize(mutex.0.as_mut_ptr()).unwrap();
        assert_eq!(store.idle(mutex.0.as_mut_ptr()), Ok(true));
        assert_eq!(count(&mutex), 1);
        assert_eq!(owner(&mutex), 0);
        assert_eq!(special_apc_disable(&first_thread), 0);

        assert_eq!(
            store.begin_wait(
                mutex.0.as_mut_ptr(),
                first,
                first_thread.0.as_mut_ptr(),
                0,
            ),
            Ok(GuardedMutexWaitAdmission::Acquired),
        );
        assert_eq!(owner(&mutex), first);
        assert_eq!(store.idle(mutex.0.as_mut_ptr()), Ok(false));
        assert_eq!(special_apc_disable(&first_thread), -1);

        let ticket = match store
            .begin_wait(
                mutex.0.as_mut_ptr(),
                second,
                second_thread.0.as_mut_ptr(),
                wake_cookie,
            )
            .unwrap()
        {
            GuardedMutexWaitAdmission::Queued(ticket) => ticket,
            GuardedMutexWaitAdmission::Acquired => panic!("contended thread acquired early"),
        };
        assert_eq!(owner(&mutex), first);
        assert_eq!(special_apc_disable(&second_thread), -1);
        assert_eq!(store.granted(mutex.0.as_mut_ptr(), second, ticket), Ok(false));
        assert_eq!(
            store.complete_wait(mutex.0.as_mut_ptr(), second, ticket),
            Err(ExecutiveSyncError::BlockingWaitRequired),
        );
        assert_eq!(
            store.release(mutex.0.as_mut_ptr(), second, second_thread.0.as_mut_ptr()),
            Err(ExecutiveSyncError::NotOwned),
        );

        assert_eq!(
            store
                .release(mutex.0.as_mut_ptr(), first, first_thread.0.as_mut_ptr())
                .unwrap(),
            Some(wake_cookie),
        );
        assert_eq!(special_apc_disable(&first_thread), 0);
        assert_eq!(owner(&mutex), 0);
        assert_eq!(store.granted(mutex.0.as_mut_ptr(), second, ticket), Ok(true));
        assert_eq!(
            store.complete_wait(mutex.0.as_mut_ptr(), second, ticket),
            Ok(()),
        );
        assert_eq!(owner(&mutex), second);
        assert_eq!(special_apc_disable(&second_thread), -1);
        assert_eq!(
            store
                .release(mutex.0.as_mut_ptr(), second, second_thread.0.as_mut_ptr())
                .unwrap(),
            None,
        );
        assert_eq!(special_apc_disable(&second_thread), 0);
        assert_eq!(owner(&mutex), 0);
        assert_eq!(count(&mutex), 1);
        store.delete(mutex.0.as_mut_ptr()).unwrap();
    }
}

#[test]
fn nested_guarded_region_is_preserved_and_recursion_is_rejected() {
    let mut mutex = Aligned([0u8; 0x40]);
    let mut thread = Aligned([0u8; 0x280]);
    let mut store = GuardedMutexStore::new();
    let owner_thread = 0x1000;

    unsafe {
        store.initialize(mutex.0.as_mut_ptr()).unwrap();
        nt_kernel_exec::executive_sync::enter_guarded_region(thread.0.as_mut_ptr()).unwrap();
        assert_eq!(special_apc_disable(&thread), -1);
        assert_eq!(
            store.begin_wait(
                mutex.0.as_mut_ptr(),
                owner_thread,
                thread.0.as_mut_ptr(),
                0,
            ),
            Ok(GuardedMutexWaitAdmission::Acquired),
        );
        assert_eq!(special_apc_disable(&thread), -2);
        assert_eq!(
            store.begin_wait(
                mutex.0.as_mut_ptr(),
                owner_thread,
                thread.0.as_mut_ptr(),
                0,
            ),
            Err(ExecutiveSyncError::GuardedMutexRecursiveAcquire),
        );
        assert_eq!(special_apc_disable(&thread), -2);
        assert_eq!(
            store.delete(mutex.0.as_mut_ptr()),
            Err(ExecutiveSyncError::ResourceBusy),
        );
        assert_eq!(
            store
                .release(mutex.0.as_mut_ptr(), owner_thread, thread.0.as_mut_ptr())
                .unwrap(),
            None,
        );
        assert_eq!(special_apc_disable(&thread), -1);
        nt_kernel_exec::executive_sync::leave_guarded_region(thread.0.as_mut_ptr()).unwrap();
        assert_eq!(special_apc_disable(&thread), 0);
        store.delete(mutex.0.as_mut_ptr()).unwrap();
    }
}

#[test]
fn cancel_wait_restores_apc_state_and_invalidates_ticket() {
    let mut mutex = Aligned([0u8; 0x40]);
    let mut first_thread = Aligned([0u8; 0x280]);
    let mut second_thread = Aligned([0u8; 0x280]);
    let mut store = GuardedMutexStore::new();

    unsafe {
        store.initialize(mutex.0.as_mut_ptr()).unwrap();
        store
            .begin_wait(mutex.0.as_mut_ptr(), 0x1000, first_thread.0.as_mut_ptr(), 0)
            .unwrap();
        let ticket = match store
            .begin_wait(mutex.0.as_mut_ptr(), 0x2000, second_thread.0.as_mut_ptr(), 0xabc0)
            .unwrap()
        {
            GuardedMutexWaitAdmission::Queued(ticket) => ticket,
            GuardedMutexWaitAdmission::Acquired => panic!("expected contention"),
        };
        assert_eq!(store.delete(mutex.0.as_mut_ptr()), Err(ExecutiveSyncError::ResourceBusy));
        assert_eq!(
            store.cancel_wait(
                mutex.0.as_mut_ptr(),
                0x2000,
                second_thread.0.as_mut_ptr(),
                ticket,
            ),
            Ok(None),
        );
        assert_eq!(special_apc_disable(&second_thread), 0);
        assert_eq!(
            store.complete_wait(mutex.0.as_mut_ptr(), 0x2000, ticket),
            Err(ExecutiveSyncError::InvalidOwner),
        );
        assert_eq!(
            store
                .release(mutex.0.as_mut_ptr(), 0x1000, first_thread.0.as_mut_ptr())
                .unwrap(),
            None,
        );
        store.delete(mutex.0.as_mut_ptr()).unwrap();
    }
}

#[test]
fn cancelling_granted_ticket_passes_gate_to_next_exact_waiter() {
    let mut mutex = Aligned([0u8; 0x40]);
    let mut owner_thread = Aligned([0u8; 0x280]);
    let mut first_thread = Aligned([0u8; 0x280]);
    let mut second_thread = Aligned([0u8; 0x280]);
    let mut store = GuardedMutexStore::new();
    unsafe {
        store.initialize(mutex.0.as_mut_ptr()).unwrap();
        store.begin_wait(mutex.0.as_mut_ptr(), 0x1000, owner_thread.0.as_mut_ptr(), 0)
            .unwrap();
        let first = match store.begin_wait(mutex.0.as_mut_ptr(), 0x2000,
            first_thread.0.as_mut_ptr(), 0xabc0).unwrap() {
            GuardedMutexWaitAdmission::Queued(ticket) => ticket,
            _ => panic!("first contender did not queue"),
        };
        let second = match store.begin_wait(mutex.0.as_mut_ptr(), 0x3000,
            second_thread.0.as_mut_ptr(), 0xdef0).unwrap() {
            GuardedMutexWaitAdmission::Queued(ticket) => ticket,
            _ => panic!("second contender did not queue"),
        };
        assert_eq!(store.granted(mutex.0.as_mut_ptr(), 0x2000, second),
            Err(ExecutiveSyncError::InvalidOwner));
        assert_eq!(store.idle(mutex.0.as_mut_ptr()), Ok(false));
        assert_eq!(store.release(mutex.0.as_mut_ptr(), 0x1000,
            owner_thread.0.as_mut_ptr()), Ok(Some(0xabc0)));
        assert_eq!(store.granted(mutex.0.as_mut_ptr(), 0x2000, first), Ok(true));
        assert_eq!(store.granted(mutex.0.as_mut_ptr(), 0x3000, second), Ok(false));
        assert_eq!(store.cancel_wait(mutex.0.as_mut_ptr(), 0x2000,
            first_thread.0.as_mut_ptr(), first), Ok(Some(0xdef0)));
        assert_eq!(special_apc_disable(&first_thread), 0);
        assert_eq!(store.granted(mutex.0.as_mut_ptr(), 0x3000, second), Ok(true));
        store.complete_wait(mutex.0.as_mut_ptr(), 0x3000, second).unwrap();
        assert_eq!(owner(&mutex), 0x3000);
        assert_eq!(store.release(mutex.0.as_mut_ptr(), 0x3000,
            second_thread.0.as_mut_ptr()), Ok(None));
        assert_eq!(special_apc_disable(&second_thread), 0);
        assert_eq!(store.idle(mutex.0.as_mut_ptr()), Ok(true));
        store.delete(mutex.0.as_mut_ptr()).unwrap();
    }
}
