//! `PEB->Ldr` construction: the three `LIST_ENTRY` module lists + the PEB/TEB fields.
//!
//! Hosted binaries (and debuggers) walk `PEB->Ldr`'s three doubly-linked lists —
//! `InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList` — to
//! enumerate loaded modules. Each list threads through a per-module `LDR_DATA_TABLE_ENTRY` at a
//! *different* `LIST_ENTRY` offset (load @ +0x00, memory @ +0x10, init @ +0x20 within the entry).
//!
//! On-target these are intrusive lists linked by **absolute VA** through entries that live in the
//! process address space. Here we build the entries + compute the *link targets* over a **model**
//! (each `LDR_DATA_TABLE_ENTRY` gets an assigned VA; the flink/blink of each list are set to the
//! neighbouring entries' list-node VAs, circular through the `PEB_LDR_DATA` list head — exactly the
//! real threading). The host test walks the built `InLoadOrder` list by following flinks and
//! recovers the modules in order. Writing these entries into live memory is the [`LoaderBuild::commit`]
//! seam (a [`super::host::LoaderHost`] call); the *layout + link math* is host-tested here.

use alloc::string::String;
use alloc::vec::Vec;

use nt_ntdll_layout::{LdrDataTableEntry, ListEntry, PebLdrData, UnicodeString};

use super::module::LoaderState;

/// Offsets of each list's `LIST_ENTRY` **within** a `LDR_DATA_TABLE_ENTRY` (x64), and within the
/// `PEB_LDR_DATA` head — the constants the link math uses. Proven against `nt-ntdll-layout`'s
/// static asserts.
pub mod link_offsets {
    /// `LDR_DATA_TABLE_ENTRY.InLoadOrderLinks` @ +0x00.
    pub const ENTRY_IN_LOAD_ORDER: u64 = 0x00;
    /// `LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks` @ +0x10.
    pub const ENTRY_IN_MEMORY_ORDER: u64 = 0x10;
    /// `LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks` @ +0x20.
    pub const ENTRY_IN_INIT_ORDER: u64 = 0x20;
    /// `PEB_LDR_DATA.InLoadOrderModuleList` @ +0x10.
    pub const HEAD_IN_LOAD_ORDER: u64 = 0x10;
    /// `PEB_LDR_DATA.InMemoryOrderModuleList` @ +0x20.
    pub const HEAD_IN_MEMORY_ORDER: u64 = 0x20;
    /// `PEB_LDR_DATA.InInitializationOrderModuleList` @ +0x30.
    pub const HEAD_IN_INIT_ORDER: u64 = 0x30;
}

/// Build a `UNICODE_STRING` descriptor for a name of `len_u16` code units (byte length + capacity
/// set; `buffer` VA filled in at commit time). Uses `Default` to zero the private padding.
fn name_unicode_string(len_u16: usize) -> UnicodeString {
    let mut u = UnicodeString::default();
    let bytes = (len_u16 * 2) as u16;
    u.length = bytes;
    u.maximum_length = bytes;
    u.buffer = 0;
    u
}

/// One built `LDR_DATA_TABLE_ENTRY` + the VA it occupies + its UTF-16 name buffers. The entry's
/// `LIST_ENTRY` fields are filled in by [`build_ldr`] once all entry VAs are known.
#[derive(Clone, Debug)]
pub struct BuiltLdrEntry {
    /// The VA this entry occupies (its `InLoadOrderLinks` is at exactly this VA).
    pub va: u64,
    /// The module base name (for matching / diagnostics).
    pub name: String,
    /// The materialized `LDR_DATA_TABLE_ENTRY` (with links threaded).
    pub entry: LdrDataTableEntry,
    /// The UTF-16 base-name buffer the entry's `base_dll_name.buffer` points at.
    pub base_name_utf16: Vec<u16>,
    /// The UTF-16 full-path buffer the entry's `full_dll_name.buffer` points at.
    pub full_name_utf16: Vec<u16>,
}

/// The built loader data: the `PEB_LDR_DATA` head + the per-module entries, all links threaded.
#[derive(Clone, Debug)]
pub struct BuiltLdr {
    /// The `PEB_LDR_DATA` at [`Self::ldr_va`].
    pub ldr: PebLdrData,
    /// The VA the `PEB_LDR_DATA` occupies.
    pub ldr_va: u64,
    /// The per-module entries, in **load order**.
    pub entries: Vec<BuiltLdrEntry>,
}

/// Layout parameters for placing the built structures in the process address space (the model VAs
/// host tests use; on-target these come from a scratch allocation).
#[derive(Copy, Clone, Debug)]
pub struct LdrLayout {
    /// The VA to place the `PEB_LDR_DATA` head at.
    pub ldr_va: u64,
    /// The VA of the first `LDR_DATA_TABLE_ENTRY`; subsequent entries are spaced by [`Self::stride`].
    pub first_entry_va: u64,
    /// The spacing between consecutive entry VAs (must be ≥ `size_of::<LdrDataTableEntry>()`;
    /// leaves room for the name buffers in the same model region).
    pub stride: u64,
}

impl Default for LdrLayout {
    fn default() -> Self {
        // Arbitrary but plausible model VAs for host tests.
        LdrLayout {
            ldr_va: 0x0000_0000_0100_0000,
            first_entry_va: 0x0000_0000_0100_1000,
            stride: 0x400,
        }
    }
}

/// Build the `PEB->Ldr` structure: one `LDR_DATA_TABLE_ENTRY` per loaded module, threaded through
/// all three lists.
///
/// - `load_order` / `init_order` are the module orders (indices into `state.modules`) for the
///   load-order and init-order lists. The memory-order list uses load order (a reasonable model;
///   the real memory order is by base VA but load order is the common case and the threading is
///   identical).
/// - Returns a [`BuiltLdr`] whose entries carry correctly threaded `flink`/`blink` (circular,
///   through the `PEB_LDR_DATA` head), ready for the [`super::host::LoaderHost`] to commit.
pub fn build_ldr(
    state: &LoaderState,
    load_order: &[usize],
    init_order: &[usize],
    layout: LdrLayout,
) -> BuiltLdr {
    let n = load_order.len();

    // Assign a VA to each MODULE index, following load order for placement.
    let mut entry_va = alloc::vec![0u64; state.modules.len()];
    for (pos, &mi) in load_order.iter().enumerate() {
        entry_va[mi] = layout.first_entry_va + (pos as u64) * layout.stride;
    }

    // Materialize each entry (fields first; links after).
    let mut entries: Vec<BuiltLdrEntry> = Vec::with_capacity(n);
    for &mi in load_order {
        let m = &state.modules[mi];
        let base_name_utf16: Vec<u16> = m.name.encode_utf16().collect();
        let full_name_utf16: Vec<u16> = m.name.encode_utf16().collect(); // model: full == base
        let va = entry_va[mi];

        // `Default` zeroes the struct (incl. the private `_pad`s in the layout crate); we then set
        // the public fields. Constructing via a literal isn't possible from here (private padding).
        let mut entry = LdrDataTableEntry::default();
        entry.in_load_order_links = ListEntry::default();
        entry.in_memory_order_links = ListEntry::default();
        entry.in_initialization_order_links = ListEntry::default();
        entry.dll_base = m.base;
        entry.entry_point = if m.entry_point_rva != 0 {
            m.base.wrapping_add(m.entry_point_rva as u64)
        } else {
            0
        };
        entry.size_of_image = m.size_of_image;
        entry.full_dll_name = name_unicode_string(full_name_utf16.len());
        entry.base_dll_name = name_unicode_string(base_name_utf16.len());
        entry.load_count = 1;
        entry.tls_index = 0;
        entry.flags = if m.has_tls { 0x0000_0400 } else { 0 }; // LDRP TLS marker (model)

        entries.push(BuiltLdrEntry {
            va,
            name: m.name.clone(),
            entry,
            base_name_utf16,
            full_name_utf16,
        });
    }

    // Thread the three lists. Each list is circular through the corresponding PEB_LDR_DATA head
    // LIST_ENTRY. A list node's VA = entry_va + node_offset (head node VA = ldr_va + head_offset).
    thread_list(
        &mut entries,
        load_order,
        &entry_va,
        layout.ldr_va + link_offsets::HEAD_IN_LOAD_ORDER,
        link_offsets::ENTRY_IN_LOAD_ORDER,
        ListSel::Load,
    );
    // Memory order uses load order in this model.
    thread_list(
        &mut entries,
        load_order,
        &entry_va,
        layout.ldr_va + link_offsets::HEAD_IN_MEMORY_ORDER,
        link_offsets::ENTRY_IN_MEMORY_ORDER,
        ListSel::Memory,
    );
    thread_list(
        &mut entries,
        init_order,
        &entry_va,
        layout.ldr_va + link_offsets::HEAD_IN_INIT_ORDER,
        link_offsets::ENTRY_IN_INIT_ORDER,
        ListSel::Init,
    );

    // Build the head with the three list-head LIST_ENTRYs pointing at the first/last node of each.
    let head_load = build_head_links(&entries, load_order, &entry_va, layout, ListSel::Load);
    let head_mem = build_head_links(&entries, load_order, &entry_va, layout, ListSel::Memory);
    let head_init = build_head_links(&entries, init_order, &entry_va, layout, ListSel::Init);

    let mut ldr = PebLdrData::default();
    ldr.length = core::mem::size_of::<PebLdrData>() as u32;
    ldr.initialized = 1;
    ldr.in_load_order_module_list = head_load;
    ldr.in_memory_order_module_list = head_mem;
    ldr.in_initialization_order_module_list = head_init;

    BuiltLdr {
        ldr,
        ldr_va: layout.ldr_va,
        entries,
    }
}

/// Which of the three lists a threading pass is filling.
#[derive(Copy, Clone, PartialEq, Eq)]
enum ListSel {
    Load,
    Memory,
    Init,
}

/// Thread one list (in `order`) circularly through the head at `head_node_va`, each entry's list
/// node at `entry_va[mi] + node_off`. Sets each entry's `flink`/`blink` for the selected list.
fn thread_list(
    entries: &mut [BuiltLdrEntry],
    order: &[usize],
    entry_va: &[u64],
    head_node_va: u64,
    node_off: u64,
    sel: ListSel,
) {
    let node_va = |mi: usize| entry_va[mi] + node_off;
    // Precompute each ordered module's index into `entries` (entries are in load order; matched by
    // VA) so we don't hold an immutable borrow of `entries` while mutating it below.
    let ei_of: Vec<usize> = order
        .iter()
        .map(|&mi| {
            entries
                .iter()
                .position(|e| e.va == entry_va[mi])
                .expect("entry present")
        })
        .collect();

    let count = order.len();
    for k in 0..count {
        let prev_va = if k == 0 {
            head_node_va
        } else {
            node_va(order[k - 1])
        };
        let next_va = if k + 1 == count {
            head_node_va
        } else {
            node_va(order[k + 1])
        };
        let ei = ei_of[k];
        let links = match sel {
            ListSel::Load => &mut entries[ei].entry.in_load_order_links,
            ListSel::Memory => &mut entries[ei].entry.in_memory_order_links,
            ListSel::Init => &mut entries[ei].entry.in_initialization_order_links,
        };
        links.flink = next_va;
        links.blink = prev_va;
    }
}

/// Build the `PEB_LDR_DATA` head `LIST_ENTRY` for one list: `flink` → first node, `blink` → last
/// node (circular; empty list points at itself).
fn build_head_links(
    _entries: &[BuiltLdrEntry],
    order: &[usize],
    entry_va: &[u64],
    layout: LdrLayout,
    sel: ListSel,
) -> ListEntry {
    let (head_off, node_off) = match sel {
        ListSel::Load => (link_offsets::HEAD_IN_LOAD_ORDER, link_offsets::ENTRY_IN_LOAD_ORDER),
        ListSel::Memory => (
            link_offsets::HEAD_IN_MEMORY_ORDER,
            link_offsets::ENTRY_IN_MEMORY_ORDER,
        ),
        ListSel::Init => (link_offsets::HEAD_IN_INIT_ORDER, link_offsets::ENTRY_IN_INIT_ORDER),
    };
    let head_va = layout.ldr_va + head_off;
    if order.is_empty() {
        return ListEntry {
            flink: head_va,
            blink: head_va,
        };
    }
    let first = entry_va[order[0]] + node_off;
    let last = entry_va[order[order.len() - 1]] + node_off;
    ListEntry {
        flink: first,
        blink: last,
    }
}

/// Walk the built `InLoadOrder` list starting from the head, returning the module names in link
/// order — the exact traversal a hosted binary / debugger does. Used by the host test to prove the
/// threading is correct (walk → recover the modules).
pub fn walk_in_load_order(built: &BuiltLdr) -> Vec<String> {
    walk_list(
        built,
        built.ldr_va + link_offsets::HEAD_IN_LOAD_ORDER,
        link_offsets::ENTRY_IN_LOAD_ORDER,
        ListSel::Load,
    )
}

/// Walk the built `InInitializationOrder` list.
pub fn walk_in_init_order(built: &BuiltLdr) -> Vec<String> {
    walk_list(
        built,
        built.ldr_va + link_offsets::HEAD_IN_INIT_ORDER,
        link_offsets::ENTRY_IN_INIT_ORDER,
        ListSel::Init,
    )
}

fn walk_list(built: &BuiltLdr, head_node_va: u64, node_off: u64, sel: ListSel) -> Vec<String> {
    let mut names = Vec::new();
    // Start at head.flink.
    let head_flink = match sel {
        ListSel::Load => built.ldr.in_load_order_module_list.flink,
        ListSel::Memory => built.ldr.in_memory_order_module_list.flink,
        ListSel::Init => built.ldr.in_initialization_order_module_list.flink,
    };
    let mut cur = head_flink;
    let mut guard = 0;
    while cur != head_node_va && guard <= built.entries.len() {
        // cur is a list-node VA; the entry VA is cur - node_off.
        let entry_va = cur - node_off;
        match built.entries.iter().find(|e| e.va == entry_va) {
            Some(e) => {
                names.push(e.name.clone());
                cur = match sel {
                    ListSel::Load => e.entry.in_load_order_links.flink,
                    ListSel::Memory => e.entry.in_memory_order_links.flink,
                    ListSel::Init => e.entry.in_initialization_order_links.flink,
                };
            }
            None => break,
        }
        guard += 1;
    }
    names
}
