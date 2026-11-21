use crate::loaded_module_lookup::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

struct Memory(BTreeMap<u64, u8>);

impl Memory {
    fn put(&mut self, va: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().enumerate() {
            self.0.insert(va + offset as u64, *byte);
        }
    }

    fn read(&self, va: u64, out: &mut [u8]) -> bool {
        for (offset, byte) in out.iter_mut().enumerate() {
            match self.0.get(&(va + offset as u64)) {
                Some(value) => *byte = *value,
                None => return false,
            }
        }
        true
    }
}

const TEB: u64 = 0x1000;
const PEB: u64 = 0x2000;
const LDR: u64 = 0x3000;

fn process(modules: &[(u64, u32, &str)]) -> Memory {
    let mut memory = Memory(BTreeMap::new());
    memory.put(TEB + 0x60, &PEB.to_le_bytes());
    memory.put(PEB + 0x18, &LDR.to_le_bytes());
    let head = LDR + 0x10;
    let entries: Vec<u64> = (0..modules.len() as u64).map(|index| 0x4000 + index * 0x100).collect();
    memory.put(head, &entries.first().copied().unwrap_or(head).to_le_bytes());
    for (index, &(base, size, name)) in modules.iter().enumerate() {
        let entry = entries[index];
        let next = entries.get(index + 1).copied().unwrap_or(head);
        memory.put(entry, &next.to_le_bytes());
        memory.put(entry + 0x30, &base.to_le_bytes());
        memory.put(entry + 0x40, &u64::from(size).to_le_bytes());
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let buffer = entry + 0x80;
        memory.put(buffer, &units);
        let mut string = [0u8; 16];
        string[..2].copy_from_slice(&(units.len() as u16).to_le_bytes());
        string[8..].copy_from_slice(&buffer.to_le_bytes());
        memory.put(entry + 0x58, &string);
    }
    memory
}

fn name(module: &LoadedModule) -> alloc::string::String {
    alloc::string::String::from_utf16(&module.name[..module.name_units]).unwrap()
}

#[test]
fn names_the_relocated_image_that_contains_the_fault() {
    let memory = process(&[
        (0x1_4000_0000, 0x1a_6000, "cmd.exe"),
        (0x100_3043_0000, 0x3_0000, "relocated.dll"),
        (0x7ff_6d00_0000, 0x2_5000, "apphelp.dll"),
    ]);
    let module = module_containing(TEB, 0x100_3045_2339, |va, out| memory.read(va, out)).unwrap();
    assert_eq!((module.base, module.size), (0x100_3043_0000, 0x3_0000));
    assert_eq!(name(&module), "relocated.dll");
}

#[test]
fn an_address_outside_every_image_or_an_unreadable_list_names_nothing() {
    let memory = process(&[(0x1_4000_0000, 0x1000, "cmd.exe")]);
    assert_eq!(module_containing(TEB, 0x1_4000_1000, |va, out| memory.read(va, out)), None);
    assert_eq!(module_containing(0x9000, 0x1_4000_0000, |va, out| memory.read(va, out)), None);
}
