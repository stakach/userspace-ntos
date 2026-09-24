//! Hosted NT I/O share-access exports over x64 WDM file-object memory.

use nt_io_manager::share_access::{FileShareState, ShareAccessCounters};

const FILE_SHARE_FLAGS_OFFSET: usize = 0x50;
const FILE_SHARE_BOOLS_OFFSET: usize = 0x4a;
const FO_FILE_OBJECT_HAS_EXTENSION: u32 = 0x0080_0000;

unsafe fn file_state(file_object: *mut u8) -> (FileShareState, bool) {
    assert!(
        !file_object.is_null(),
        "Io share access requires a FILE_OBJECT"
    );
    let booleans =
        core::ptr::read_unaligned(file_object.add(FILE_SHARE_BOOLS_OFFSET) as *const [u8; 6]);
    let flags = core::ptr::read_unaligned(file_object.add(FILE_SHARE_FLAGS_OFFSET) as *const u32);
    (
        FileShareState {
            read: booleans[0] != 0,
            write: booleans[1] != 0,
            delete: booleans[2] != 0,
            shared_read: booleans[3] != 0,
            shared_write: booleans[4] != 0,
            shared_delete: booleans[5] != 0,
        },
        flags & FO_FILE_OBJECT_HAS_EXTENSION != 0,
    )
}

unsafe fn write_file_state(file_object: *mut u8, file: &FileShareState) {
    core::ptr::write_unaligned(
        file_object.add(FILE_SHARE_BOOLS_OFFSET) as *mut [u8; 6],
        [
            file.read as u8,
            file.write as u8,
            file.delete as u8,
            file.shared_read as u8,
            file.shared_write as u8,
            file.shared_delete as u8,
        ],
    );
}

unsafe fn counters(share_access: *mut u8) -> ShareAccessCounters {
    assert!(
        !share_access.is_null(),
        "Io share access requires SHARE_ACCESS"
    );
    let word = |index: usize| core::ptr::read_unaligned(share_access.add(index * 4) as *const u32);
    ShareAccessCounters {
        open_count: word(0),
        readers: word(1),
        writers: word(2),
        deleters: word(3),
        shared_read: word(4),
        shared_write: word(5),
        shared_delete: word(6),
    }
}

unsafe fn write_counters(share_access: *mut u8, state: &ShareAccessCounters) {
    let words = [
        state.open_count,
        state.readers,
        state.writers,
        state.deleters,
        state.shared_read,
        state.shared_write,
        state.shared_delete,
    ];
    for (index, word) in words.iter().enumerate() {
        core::ptr::write_unaligned(share_access.add(index * 4) as *mut u32, *word);
    }
}

pub(super) extern "win64" fn check(
    desired_access: u32,
    desired_share_access: u32,
    file_object: *mut u8,
    share_access: *mut u8,
    update: u8,
) -> u32 {
    unsafe {
        let (mut file, has_extension) = file_state(file_object);
        let mut state = counters(share_access);
        let result = state.check(
            desired_access,
            desired_share_access,
            &mut file,
            update != 0,
            has_extension,
        );
        write_file_state(file_object, &file);
        if result.is_ok() && update != 0 {
            write_counters(share_access, &state);
        }
        result.err().unwrap_or(0)
    }
}

pub(super) extern "win64" fn set(
    desired_access: u32,
    desired_share_access: u32,
    file_object: *mut u8,
    share_access: *mut u8,
) {
    unsafe {
        let (mut file, has_extension) = file_state(file_object);
        let mut state = counters(share_access);
        state.set(
            desired_access,
            desired_share_access,
            &mut file,
            has_extension,
        );
        write_file_state(file_object, &file);
        if !has_extension {
            write_counters(share_access, &state);
        }
    }
}

pub(super) extern "win64" fn update(file_object: *mut u8, share_access: *mut u8) {
    unsafe {
        let (file, has_extension) = file_state(file_object);
        if has_extension {
            return;
        }
        let mut state = counters(share_access);
        state.update(&file, false);
        write_counters(share_access, &state);
    }
}

pub(super) extern "win64" fn remove(file_object: *mut u8, share_access: *mut u8) {
    unsafe {
        let (file, has_extension) = file_state(file_object);
        if has_extension {
            return;
        }
        let mut state = counters(share_access);
        state.remove(&file, false);
        write_counters(share_access, &state);
    }
}
