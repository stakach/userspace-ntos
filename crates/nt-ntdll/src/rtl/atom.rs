//! Atom-table `Rtl*` stragglers — **reuse** [`nt_kernel_exec::rtl_atom`].
//!
//! The `RtlAddAtomToAtomTable` / `RtlLookupAtomInAtomTable` / `RtlDeleteAtomFromAtomTable` /
//! `RtlQueryAtomInAtomTable` / `RtlCreateAtomTable` family maps directly onto the host-tested
//! [`nt_kernel_exec::rtl_atom::OwnedAtomTable`]. We re-export it and provide the thin ntdll-named
//! wrappers so a binary linking the `Rtl*Atom*` names resolves against our ntdll — without a second
//! atom-table implementation.

pub use nt_kernel_exec::rtl_atom::{
    check_integer_atom, AtomListResult, AtomQueryResult, OwnedAtomTable,
};

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

/// `RtlPinAtomInAtomTable(AtomTable, Atom)`.
pub fn pin_atom(table: &mut OwnedAtomTable, atom: u16) -> u32 {
    table.pin(atom)
}

/// `RtlEmptyAtomTable(AtomTable, DeletePinned)`.
pub fn empty_atom_table(table: &mut OwnedAtomTable, delete_pinned: bool) -> u32 {
    table.empty(delete_pinned)
}

/// Query a synthesized integer atom without requiring an atom table.
///
/// # Safety
/// Any non-null out-param must be writable. If `name` is non-null, `name_len` must point to the
/// caller-provided byte capacity.
pub unsafe fn query_integer_atom(
    atom: u16,
    ref_count: *mut u32,
    pin_count: *mut u32,
    name: *mut u16,
    name_len: *mut u32,
) -> u32 {
    unsafe {
        nt_kernel_exec::rtl_atom::query(
            core::ptr::null(),
            atom,
            ref_count,
            pin_count,
            name,
            name_len,
        )
    }
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

    #[test]
    fn pin_and_empty_atom_table() {
        let mut t = create_atom_table(37).expect("atom table");
        let pinned: alloc::vec::Vec<u16> = "PinnedClass".encode_utf16().collect();
        let transient: alloc::vec::Vec<u16> = "TransientClass".encode_utf16().collect();

        let pinned_atom = add_atom(&mut t, &pinned).expect("add pinned");
        add_atom(&mut t, &transient).expect("add transient");
        assert_eq!(pin_atom(&mut t, pinned_atom), 0);

        assert_eq!(empty_atom_table(&mut t, false), 0);
        assert_eq!(lookup_atom(&t, &pinned), Ok(pinned_atom));
        assert!(lookup_atom(&t, &transient).is_err());

        assert_eq!(empty_atom_table(&mut t, true), 0);
        assert!(lookup_atom(&t, &pinned).is_err());
    }
}
