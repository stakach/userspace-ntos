//! Hosted IoCreateDevice must hand mountable drivers a live, separately owned VPB.

#[path = "../../../components/ntos-executive/src/hosted_driver_projection.rs"]
mod projection;

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct Pool {
    allocations: HashMap<u64, Layout>,
    remaining: Option<usize>,
}

fn pool() -> &'static Mutex<Pool> {
    static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Pool::default()))
}

unsafe fn allocate(size: u64) -> u64 {
    let mut pool = pool().lock().unwrap();
    if let Some(remaining) = &mut pool.remaining {
        if *remaining == 0 {
            return 0;
        }
        *remaining -= 1;
    }
    let layout = Layout::from_size_align(size as usize, 16).unwrap();
    let address = alloc_zeroed(layout) as u64;
    if address != 0 {
        pool.allocations.insert(address, layout);
    }
    address
}

unsafe fn free(address: u64) {
    let layout = pool().lock().unwrap().allocations.remove(&address).unwrap();
    dealloc(address as *mut u8, layout);
}

fn outstanding() -> usize {
    pool().lock().unwrap().allocations.len()
}

#[test]
fn source_projection_leaves_vpb_for_authenticated_executive_publication() {
    let mut driver = [0u64; 42];
    let driver_address = driver.as_mut_ptr() as u64;

    for device_type in [0x07, 0x24, 0x02, 0x1f] {
        let projection = unsafe {
            projection::create_hosted_device_projection(
                driver_address, 0x200, device_type, 0x80, 0, allocate, free,
            )
        }
        .unwrap();
        let device = projection.device_object();
        let vpb = unsafe { ((device + 0x38) as *const u64).read_unaligned() };
        assert_eq!(vpb, 0, "source domain must not choose VPB owner for {device_type:#x}");
        assert_eq!(outstanding(), 1);

        unsafe { projection::delete_hosted_device_projection(projection, free) };
        assert_eq!(driver[1], 0, "deleted device must leave DriverObject list");
        assert_eq!(outstanding(), 0);
    }

    let ordinary = unsafe {
        projection::create_hosted_device_projection(
            driver_address, 0, 0x22, 0x80, 0, allocate, free,
        )
    }
    .unwrap();
    assert_eq!(unsafe { ((ordinary.device_object() + 0x38) as *const u64).read_unaligned() }, 0);
    assert_eq!(outstanding(), 1);
    unsafe { projection::delete_hosted_device_projection(ordinary, free) };
    assert_eq!(outstanding(), 0);

    pool().lock().unwrap().remaining = Some(0);
    let failure = unsafe {
        projection::create_hosted_device_projection(
            driver_address, 0x200, 0x07, 0x80, 0, allocate, free,
        )
    };
    assert_eq!(failure.err(), Some(0xC000_009Au32 as i32));
    assert_eq!(driver[1], 0, "failed device allocation cannot publish device");
    assert_eq!(outstanding(), 0);
}
