//! Atom-table `Rtl*` stragglers — **reuse** [`nt_kernel_exec::rtl_atom`].
//!
//! The `RtlAddAtomToAtomTable` / `RtlLookupAtomInAtomTable` / `RtlDeleteAtomFromAtomTable` /
//! `RtlQueryAtomInAtomTable` / `RtlCreateAtomTable` family maps directly onto the host-tested
//! [`nt_kernel_exec::rtl_atom::OwnedAtomTable`]. We re-export it and provide the thin ntdll-named
//! wrappers so a binary linking the `Rtl*Atom*` names resolves against our ntdll — without a second
//! atom-table implementation.

pub use nt_kernel_exec::rtl_atom::{AtomListResult, AtomQueryResult, OwnedAtomTable};

/// `RtlCreateAtomTable(NumberOfBuckets, AtomTable*)` — a new atom table sized for `capacity` atoms.
pub fn create_atom_table(capacity: usize) -> Option<OwnedAtomTable> {
    OwnedAtomTable::with_capacity(capacity)
}

/// `RtlAddAtomToAtomTable(AtomTable, AtomName, Atom*)` — add a string atom, returning its atom id.
pub fn add_atom(table: &mut OwnedAtomTable, name: &[u16]) -> Result<u16, u32> {
    table.add_name(name)
}

/// `RtlAddAtomToAtomTable` for an integer atom (`0xC000..=0xFFFF`).
pub fn add_integer_atom(table: &mut OwnedAtomTable, atom: u16) -> Result<u16, u32> {
    table.add_integer(atom)
}

/// `RtlLookupAtomInAtomTable(AtomTable, AtomName, Atom*)` — find a string atom.
pub fn lookup_atom(table: &OwnedAtomTable, name: &[u16]) -> Result<u16, u32> {
    table.find_name(name)
}

/// `RtlDeleteAtomFromAtomTable(AtomTable, Atom)` — delete an atom, returning the NTSTATUS.
pub fn delete_atom(table: &mut OwnedAtomTable, atom: u16) -> u32 {
    table.delete(atom)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn atom_add_lookup_delete() {
        let mut t = create_atom_table(37).expect("atom table");
        let name: alloc::vec::Vec<u16> = "MyClass".encode_utf16().collect();
        let a = add_atom(&mut t, &name).expect("add");
        assert_eq!(lookup_atom(&t, &name), Ok(a));
        // Delete then miss.
        assert_eq!(delete_atom(&mut t, a), 0); // STATUS_SUCCESS
        assert!(lookup_atom(&t, &name).is_err());
    }

    #[test]
    fn integer_atoms() {
        // Integer atoms are MAKEINTATOM values below the dynamic-atom base (0xC000); the atom IS the
        // value and never touches the table.
        let mut t = create_atom_table(37).expect("atom table");
        let a = add_integer_atom(&mut t, 0x0042).expect("int atom");
        assert_eq!(a, 0x0042);
        // A value in the dynamic range (>= 0xC000) is rejected.
        assert!(add_integer_atom(&mut t, 0xC001).is_err());
    }
}
