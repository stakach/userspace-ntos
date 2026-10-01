//! Shared image facts; native capability and load-reference ownership stays in the root loader.

use super::*;

pub(super) const GDI_DRIVER_LEAF_CAP: usize = 255;

#[derive(Clone, Copy)]
pub(super) struct GdiDriverRecord {
    pub(super) leaf: [u8; GDI_DRIVER_LEAF_CAP],
    pub(super) leaf_len: u8,
    pub(super) image: u64,
    pub(super) entry: u64,
    pub(super) expdir: u64,
    pub(super) image_len: u32,
}

impl GdiDriverRecord {
    const EMPTY: Self = Self {
        leaf: [0; GDI_DRIVER_LEAF_CAP],
        leaf_len: 0,
        image: 0,
        entry: 0,
        expdir: 0,
        image_len: 0,
    };

    pub(super) fn leaf_bytes(&self) -> &[u8] {
        &self.leaf[..self.leaf_len as usize]
    }
}

const GDI_DRIVER_RECORD_INITIAL_CAP: u64 = 4;
static GDI_DRIVER_RECORDS_PTR: AtomicU64 = AtomicU64::new(0);
static GDI_DRIVER_RECORDS_LEN: AtomicU64 = AtomicU64::new(0);
static GDI_DRIVER_RECORDS_CAP: AtomicU64 = AtomicU64::new(0);

pub(super) fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

pub(super) unsafe fn gdi_driver_record_ptr(base: u64, index: u64) -> *mut GdiDriverRecord {
    (base + index * core::mem::size_of::<GdiDriverRecord>() as u64) as *mut GdiDriverRecord
}

pub(super) unsafe fn ensure_gdi_driver_record_capacity(required: u64) -> bool {
    let cap = GDI_DRIVER_RECORDS_CAP.load(Ordering::Relaxed);
    if cap >= required {
        return true;
    }
    let mut new_cap = if cap == 0 {
        GDI_DRIVER_RECORD_INITIAL_CAP
    } else {
        cap.saturating_mul(2)
    };
    while new_cap < required {
        let next = new_cap.saturating_mul(2);
        if next <= new_cap {
            return false;
        }
        new_cap = next;
    }
    let Some(bytes) = (core::mem::size_of::<GdiDriverRecord>() as u64).checked_mul(new_cap) else {
        return false;
    };
    let new_base = pool_alloc(bytes);
    if new_base == 0 {
        return false;
    }
    let old_base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
    let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Relaxed);
    if old_base != 0 {
        for index in 0..len {
            let rec = read_volatile(gdi_driver_record_ptr(old_base, index));
            write_volatile(gdi_driver_record_ptr(new_base, index), rec);
        }
    }
    GDI_DRIVER_RECORDS_PTR.store(new_base, Ordering::Release);
    GDI_DRIVER_RECORDS_CAP.store(new_cap, Ordering::Release);
    true
}

pub(crate) fn register_gdi_driver_image(
    leaf: &[u8],
    image: u64,
    entry: u64,
    expdir: u64,
    image_len: u32,
) -> bool {
    if leaf.is_empty() || leaf.len() > GDI_DRIVER_LEAF_CAP || image == 0 || image_len == 0 {
        return false;
    }
    let record = registered_gdi_driver_record(leaf, image, entry, expdir, image_len);
    unsafe {
        let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Relaxed);
        let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
        if base != 0 {
            for index in 0..len {
                let ptr = gdi_driver_record_ptr(base, index);
                let rec = read_volatile(ptr);
                if ascii_eq_ignore_case(rec.leaf_bytes(), leaf) {
                    return rec.image == record.image
                        && rec.entry == record.entry
                        && rec.expdir == record.expdir
                        && rec.image_len == record.image_len;
                }
            }
        }
        let Some(required) = len.checked_add(1) else {
            return false;
        };
        if !ensure_gdi_driver_record_capacity(required) {
            return false;
        }
        let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
        if base == 0 {
            return false;
        }
        write_volatile(gdi_driver_record_ptr(base, len), record);
        GDI_DRIVER_RECORDS_LEN.store(required, Ordering::Release);
        true
    }
}

pub(super) fn registered_gdi_driver_record(
    leaf: &[u8],
    image: u64,
    entry: u64,
    expdir: u64,
    image_len: u32,
) -> GdiDriverRecord {
    let mut rec = GdiDriverRecord::EMPTY;
    rec.leaf_len = leaf.len() as u8;
    for (idx, &b) in leaf.iter().enumerate() {
        rec.leaf[idx] = b.to_ascii_lowercase();
    }
    rec.image = image;
    rec.entry = entry;
    rec.expdir = expdir;
    rec.image_len = image_len;
    rec
}

pub(super) fn registered_gdi_driver_for_leaf(leaf: &[u8]) -> Option<GdiDriverRecord> {
    unsafe {
        let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Acquire);
        let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        for index in 0..len {
            let rec = read_volatile(gdi_driver_record_ptr(base, index));
            if ascii_eq_ignore_case(rec.leaf_bytes(), leaf) {
                return Some(rec);
            }
        }
    }
    None
}

pub(crate) fn gdi_driver_registered(leaf: &[u8]) -> bool {
    registered_gdi_driver_for_leaf(leaf).is_some()
}

pub(super) unsafe fn image_containing(address: u64) -> Option<(u64, usize)> {
    let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Acquire);
    let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    for index in 0..len {
        let record = read_volatile(gdi_driver_record_ptr(base, index));
        let end = record.image.checked_add(u64::from(record.image_len))?;
        if (record.image..end).contains(&address) {
            return Some((record.image, record.image_len as usize));
        }
    }
    None
}
