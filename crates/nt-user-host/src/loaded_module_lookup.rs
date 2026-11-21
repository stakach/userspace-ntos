//! Name the loaded image that contains an address, from the process's own loader lists.
//!
//! A user fault inside a relocated DLL reports only an instruction pointer in the section-view
//! range (boot 44887442144: cmd.exe faulted at 0x10030452339 during `LoadLibraryExW`). The loader
//! keeps every mapped image in `PEB->Ldr->InLoadOrderModuleList`; this walks that list through a
//! bounded reader of client memory and returns the entry whose image range contains the address.

/// `TEB.ProcessEnvironmentBlock`, `PEB.Ldr` and `PEB_LDR_DATA.InLoadOrderModuleList` on x64.
const TEB_PEB: u64 = 0x60;
const PEB_LDR: u64 = 0x18;
const LDR_IN_LOAD_ORDER: u64 = 0x10;
/// `LDR_DATA_TABLE_ENTRY` on x64: `InLoadOrderLinks` is first.
const ENTRY_DLL_BASE: u64 = 0x30;
const ENTRY_SIZE_OF_IMAGE: u64 = 0x40;
const ENTRY_BASE_DLL_NAME: u64 = 0x58;
const ENTRY_FLAGS: u64 = 0x68;
/// Entries examined before the walk gives up on a corrupt or cyclic list.
pub const MODULE_WALK_LIMIT: usize = 256;
/// UTF-16 units of the base name returned.
pub const MODULE_NAME_UNITS: usize = 32;

/// The loaded image containing an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadedModule {
    pub base: u64,
    pub size: u32,
    pub name: [u16; MODULE_NAME_UNITS],
    pub name_units: usize,
    /// `LDR_DATA_TABLE_ENTRY.Flags` (`LDRP_PROCESS_ATTACH_CALLED` is 0x80000).
    pub flags: u32,
    /// Loaded modules whose base name equals this one's, ignoring ASCII case, this one included.
    /// Boot 44892262807: cmd.exe's kernelbase.dll ran code with its DllMain-initialized locale
    /// table still NULL, so the record must show whether a second copy was loaded.
    pub same_name: usize,
}

/// Find the module containing `address` in the process whose TEB is at `teb`. `read` copies
/// client memory and returns false when the range is not readable.
pub fn module_containing(
    teb: u64,
    address: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Option<LoadedModule> {
    let mut word = |va: u64, read: &mut dyn FnMut(u64, &mut [u8]) -> bool| {
        let mut bytes = [0u8; 8];
        read(va, &mut bytes).then(|| u64::from_le_bytes(bytes))
    };
    let peb = word(teb.checked_add(TEB_PEB)?, &mut read)?;
    let ldr = word(peb.checked_add(PEB_LDR)?, &mut read)?;
    let head = ldr.checked_add(LDR_IN_LOAD_ORDER)?;
    let mut entries = [0u64; MODULE_WALK_LIMIT];
    let mut count = 0usize;
    let mut entry = word(head, &mut read)?;
    while entry != head && entry != 0 && count < MODULE_WALK_LIMIT {
        entries[count] = entry;
        count += 1;
        entry = word(entry, &mut read)?;
    }
    let mut found = None;
    for &entry in &entries[..count] {
        let base = word(entry.checked_add(ENTRY_DLL_BASE)?, &mut read)?;
        let size = word(entry.checked_add(ENTRY_SIZE_OF_IMAGE)?, &mut read)? as u32;
        if address >= base && address - base < u64::from(size) {
            let flags = word(entry.checked_add(ENTRY_FLAGS)?, &mut read)? as u32;
            let mut module = LoadedModule {
                base, size, name: [0; MODULE_NAME_UNITS], name_units: 0, flags, same_name: 0,
            };
            (module.name, module.name_units) = base_name(entry, &mut read);
            found = Some(module);
            break;
        }
    }
    let mut module = found?;
    for &entry in &entries[..count] {
        let (name, units) = base_name(entry, &mut read);
        if units == module.name_units
            && name[..units].iter().zip(&module.name[..units]).all(|(a, b)| fold(*a) == fold(*b))
        {
            module.same_name += 1;
        }
    }
    Some(module)
}

fn fold(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) { unit + 0x20 } else { unit }
}

fn base_name(
    entry: u64,
    read: &mut impl FnMut(u64, &mut [u8]) -> bool,
) -> ([u16; MODULE_NAME_UNITS], usize) {
    let mut name = [0u16; MODULE_NAME_UNITS];
    let mut string = [0u8; 16];
    let Some(address) = entry.checked_add(ENTRY_BASE_DLL_NAME) else { return (name, 0) };
    if !read(address, &mut string) {
        return (name, 0);
    }
    let units = (usize::from(u16::from_le_bytes([string[0], string[1]])) / 2).min(MODULE_NAME_UNITS);
    let buffer = u64::from_le_bytes(string[8..16].try_into().unwrap());
    let mut bytes = [0u8; MODULE_NAME_UNITS * 2];
    if buffer == 0 || !read(buffer, &mut bytes[..units * 2]) {
        return (name, 0);
    }
    for (index, unit) in name.iter_mut().take(units).enumerate() {
        *unit = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }
    (name, units)
}
