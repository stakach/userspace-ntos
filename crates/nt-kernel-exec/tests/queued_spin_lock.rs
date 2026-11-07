use core::sync::atomic::AtomicU64;
use nt_kernel_exec::queued_spin_lock::{release, try_acquire, QueuedSpinError};

#[test]
fn in_stack_handle_excludes_waiters_and_controls_release() {
    let lock = AtomicU64::new(0);
    assert_eq!(try_acquire(&lock, 0x1000), Ok(true));
    assert_eq!(try_acquire(&lock, 0x2000), Ok(false));
    assert_eq!(try_acquire(&lock, 0x1000), Err(QueuedSpinError::Reentrant));
    assert_eq!(release(&lock, 0x2000), Err(QueuedSpinError::NotOwner));
    assert_eq!(release(&lock, 0x1000), Ok(()));
    assert_eq!(try_acquire(&lock, 0x2000), Ok(true));
    assert_eq!(release(&lock, 0x2000), Ok(()));
}
