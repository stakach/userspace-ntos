//! PCI's broadcast worker must run on the only published CPU or fail closed.

use nt_kernel_exec::ipi_broadcast::{admit, IpiAdmission};

const IMAGE_BASE: u64 = 0x1000_0000;
const IMAGE_LEN: u64 = 0x20_000;

#[test]
fn one_cpu_accepts_only_a_callback_inside_its_live_image() {
    assert_eq!(admit(1, IMAGE_BASE + 0x100, IMAGE_BASE, IMAGE_LEN), IpiAdmission::Local);
    assert_eq!(admit(1, 0, IMAGE_BASE, IMAGE_LEN), IpiAdmission::InvalidCallback);
    assert_eq!(admit(1, IMAGE_BASE - 1, IMAGE_BASE, IMAGE_LEN), IpiAdmission::InvalidCallback);
    assert_eq!(admit(1, IMAGE_BASE + IMAGE_LEN, IMAGE_BASE, IMAGE_LEN), IpiAdmission::InvalidCallback);
    assert_eq!(admit(1, 0x100, u64::MAX - 2, 16), IpiAdmission::InvalidCallback);
}

#[test]
fn multiple_cpus_cannot_use_the_local_callback_as_a_fake_broadcast() {
    assert_eq!(admit(4, IMAGE_BASE + 0x100, IMAGE_BASE, IMAGE_LEN), IpiAdmission::NeedsBroadcast);
    assert_eq!(admit(0, IMAGE_BASE + 0x100, IMAGE_BASE, IMAGE_LEN), IpiAdmission::InvalidTopology);
}
