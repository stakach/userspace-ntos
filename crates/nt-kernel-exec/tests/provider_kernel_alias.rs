use nt_kernel_exec::provider_kernel_alias::{KernelAliasError, KernelAliasWindow};
use nt_kernel_exec::provider_pool::PoolMemory;

const PROBE: u64 = 0x0000_7fff_ffff_0000;
const BASE: u64 = PROBE + 0x1000;
const BYTES: usize = 0xe000;

struct Memory(Vec<u8>);

impl PoolMemory for Memory {
    fn len(&self) -> u64 { self.0.len() as u64 }
    fn read_u64(&self, offset: u64) -> Option<u64> {
        let bytes = self.0.get(offset as usize..offset as usize + 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
    fn write_u64(&mut self, offset: u64, value: u64) -> bool {
        let Some(bytes) = self.0.get_mut(offset as usize..offset as usize + 8) else { return false; };
        bytes.copy_from_slice(&value.to_le_bytes());
        true
    }
    fn zero(&mut self, offset: u64, len: u64) -> bool {
        let Some(bytes) = self.0.get_mut(offset as usize..offset as usize + len as usize) else { return false; };
        bytes.fill(0);
        true
    }
}

#[test]
fn captured_cursor_pool_is_kernel_classified_and_exactly_reclaimable() {
    let window = KernelAliasWindow::new(BASE, BYTES as u64, PROBE).unwrap();
    let mut memory = Memory(vec![0; BYTES]);
    window.initialize(&mut memory).unwrap();

    let live = window.allocate(&mut memory, 2728).unwrap();
    assert!(live.address > PROBE);
    assert!(live.address + live.capacity <= BASE + BYTES as u64);
    assert_eq!(window.allocation_capacity(&memory, live.address), Ok(live.capacity));
    assert_eq!(window.free(&mut memory, live.address), Ok(()));
    assert_eq!(window.free(&mut memory, live.address), Err(KernelAliasError::NotAllocated));
    assert_eq!(window.free(&mut memory, BASE - 0x10), Err(KernelAliasError::OutsideWindow));
}

#[test]
fn high_alias_rejects_oversize_without_effect() {
    let window = KernelAliasWindow::new(BASE, BYTES as u64, PROBE).unwrap();
    let mut memory = Memory(vec![0; BYTES]);
    window.initialize(&mut memory).unwrap();
    assert_eq!(window.allocate(&mut memory, BYTES as u64), Err(KernelAliasError::OutOfMemory));
    let live = window.allocate(&mut memory, 2728).unwrap();
    assert!(live.address > PROBE);
}

#[test]
fn alias_window_excludes_probe_and_last_reserved_page() {
    assert_eq!(
        KernelAliasWindow::new(PROBE, BYTES as u64, PROBE),
        Err(KernelAliasError::InvalidWindow),
    );
    assert_eq!(
        KernelAliasWindow::new(BASE, (BYTES + 0x1000) as u64, PROBE),
        Err(KernelAliasError::InvalidWindow),
    );
    assert_eq!(
        KernelAliasWindow::new(BASE + 1, BYTES as u64, PROBE),
        Err(KernelAliasError::InvalidWindow),
    );
}

#[test]
fn client_alias_admission_cannot_replace_live_cursor_backing() {
    let window = KernelAliasWindow::new(BASE, BYTES as u64, PROBE).unwrap();
    let mut memory = Memory(vec![0; BYTES]);
    window.initialize(&mut memory).unwrap();
    let live = window.allocate(&mut memory, 2728).unwrap();
    assert!(window.contains_page(live.address & !0xfff));
    assert!(window.contains_page(BASE));
    assert!(!window.contains_page(BASE - 0x1000));
    assert!(!window.contains_page(BASE + BYTES as u64));
    assert!(!window.contains_page(BASE + 1));
}
