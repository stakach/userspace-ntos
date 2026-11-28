//! # `nt-executive-layout` — the executive's virtual address plan
//!
//! The executive image runs in the root VSpace and in the VSpace of every component it
//! spawns. Each of those address spaces is divided into bands, and a band that grows or moves
//! must not reach its neighbours. This crate is where the bands are defined: the executive
//! takes its constants from here, [`root::REGIONS`] and [`component::REGIONS`] list them, and
//! both tables are checked for overlap when this crate compiles and again by its host tests.
//!
//! What the tables cover is every band from the file pool upward in the root VSpace, and, in
//! a component VSpace, the heap and the two bands placed against it. The root's fixed
//! mappings below the file pool (image, staging buffers, work cluster, per-process mirrors)
//! are one entry here and are laid out by the constants in the executive's `main.rs`. A
//! component's own image, pool and argument windows are declared by its spawner, which
//! refuses a heap region that overlaps another declared region.
#![no_std]

mod region;
pub use region::{first_overlap, is_ascending, Region};

pub const PAGE: u64 = 0x1000;
/// The span of one leaf page table.
pub const TABLE_SPAN: u64 = 0x20_0000;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// Heap base of every VSpace that runs the executive image: the root and each spawned
/// component. One address serves both because the allocator's metadata words are addressed
/// absolutely from it by code the VSpaces share, and nothing outside the heap tells that code
/// which VSpace it is running in. How much is reserved above it is a separate concern per kind
/// of VSpace: [`ROOT_HEAP_RESERVATION_FRAMES`] and [`COMPONENT_HEAP_MAX_FRAMES`].
pub const HEAP_BASE: u64 = 0x0000_0100_1e00_0000;
/// The root executive's heap reservation in 4 KiB frames, including its transient lane.
/// Physical pages beyond the initial commitment are mapped only when allocations need them;
/// the leaf page tables for the whole reservation are built at boot, one 4 KiB table per
/// 2 MiB. 256 MiB is three times the 84 MiB of durable heap the first logon filled.
pub const ROOT_HEAP_RESERVATION_FRAMES: u64 = 65536;
/// The largest heap a spawned component may declare. A component's VSpace keeps this band
/// above [`HEAP_BASE`] clear of its other regions.
pub const COMPONENT_HEAP_MAX_FRAMES: u64 = 22528;

/// Hosted processes whose executive-side runtime windows have fixed addresses. They are the
/// process indices below the first dynamically admitted one.
pub const STATIC_PROCESS_COUNT: usize = 7;
/// Hosted process slots, static and dynamic. Each dynamic slot owns
/// [`DYNAMIC_RUNTIME_STRIDE`] of [`root::DYNAMIC_RUNTIME`], and every slot owns
/// [`WORKER_LANES_PER_PROCESS`] lanes of [`root::WORKER_MIRRORS`].
pub const HOSTED_PROCESS_LIMIT: usize = 32;
/// Thread lanes per hosted process.
pub const WORKER_LANES_PER_PROCESS: usize = 32;
/// Executive-side mirror window of one worker lane.
pub const WORKER_MIRROR_STRIDE: u64 = 0x4_0000;

/// One hosted process's demand-fill scratch window in the root VSpace.
pub const DEMAND_SCRATCH_WINDOW: u64 = 64 * MIB;
/// A dynamic process's scratch window followed by its stack, environment and heap mirrors.
pub const DYNAMIC_RUNTIME_STRIDE: u64 = 128 * MIB;

/// Upper bound of the address range the root shares with hosted-process private memory
/// numbering. Root-only bands that need no fixed relation to the heap sit above it.
pub const PRIVATE_VM_LIMIT: u64 = 0x0000_0100_4000_0000;

/// Bands of the root executive's VSpace.
pub mod root {
    use super::*;

    /// Image, staging buffers, work cluster and the per-process mirrors of the static
    /// processes. Laid out by the executive's own constants.
    pub const FIXED_LOW: Region =
        Region::spanning("fixed low mappings", 0x0000_0100_0000_0000, FILE_POOL.base);
    /// Bump pool the file-system loader maps file contents into.
    pub const FILE_POOL: Region = Region::new("file pool", 0x0000_0100_1500_0000, 48 * MIB);
    /// The root heap: durable pages committed on demand, then the transient lane at its top.
    pub const HEAP: Region =
        Region::new("root heap", HEAP_BASE, ROOT_HEAP_RESERVATION_FRAMES * PAGE);
    /// Demand-mapped large allocations of the win32k provider.
    pub const PROVIDER_LARGE_POOL: Region =
        Region::new("provider large pool", PRIVATE_VM_LIMIT, 64 * MIB);
    /// Demand-mapped provider argument leases.
    pub const PROVIDER_BULK_ARENA: Region =
        Region::new("provider bulk arena", PROVIDER_LARGE_POOL.end(), 64 * MIB);
    /// Window of the PE loader selftest.
    pub const PE_SCRATCH: Region =
        Region::new("PE loader scratch", PROVIDER_BULK_ARENA.end(), TABLE_SPAN);
    /// Root aliases of win32k lane stacks.
    pub const WIN32K_STACK_ALIASES: Region =
        Region::new("win32k stack aliases", PE_SCRATCH.end(), 8 * MIB);
    /// Reserve-only session views of win32k's `SEC_RESERVE` Sections: the global USER heap and
    /// every desktop heap. The win32k provider maps the same pages at the same addresses, and
    /// a page is backed only once it is committed.
    pub const WIN32K_SESSION_VIEWS: Region =
        Region::new("win32k session views", 0x0000_0100_4a00_0000, 96 * MIB);
    /// Root views of hosted driver images and their private windows.
    pub const DRIVER_HOST_VIEWS: Region = Region::spanning(
        "driver host views",
        0x0000_0100_5000_0000,
        0x0000_0101_5000_0000,
    );
    /// Root aliases of the hosted KUSER page, the debug filter page and exception-image
    /// snapshots.
    pub const DIAGNOSTIC_ALIASES: Region =
        Region::new("diagnostic aliases", DRIVER_HOST_VIEWS.end(), 32 * MIB);
    /// Root aliases of hosted driver worker lanes.
    pub const DRIVER_WORKER_ALIASES: Region =
        Region::new("driver worker aliases", 0x0000_0102_0000_0000, 4 * GIB);
    /// Root views of contiguous RAM leased to hosted drivers.
    pub const CONTIGUOUS_RAM_APERTURE: Region = Region::new(
        "contiguous RAM aperture",
        DRIVER_WORKER_ALIASES.end(),
        512 * MIB,
    );
    /// Mirrors of hosted worker lanes outside the legacy slots.
    pub const WORKER_MIRRORS: Region =
        Region::new("worker lane mirrors", 0x0000_0104_0000_0000, 4 * GIB);
    /// One [`DEMAND_SCRATCH_WINDOW`] per static process, indexed by process index. The windows
    /// have no fixed relation to the heap; they followed it until it needed their addresses.
    pub const STATIC_SCRATCH: Region = Region::new(
        "static process scratch windows",
        WORKER_MIRRORS.end(),
        STATIC_PROCESS_COUNT as u64 * DEMAND_SCRATCH_WINDOW,
    );
    /// Stack, environment and heap mirrors of the last static process.
    pub const SHELL_MIRRORS: Region =
        Region::new("shell process mirrors", STATIC_SCRATCH.end(), 4 * MIB);
    /// Virtual slots of owned scatter-gather graphs. They are mapped in driver-host VSpaces;
    /// the root keeps the same band clear.
    pub const DMA_GRAPH_SLOTS: Region =
        Region::new("DMA graph slots", 0x0000_0106_0000_0000, 256 * MIB);
    /// Private stacks and IPC buffers of native executive executor TCBs. The first page of
    /// each stack is deliberately left unmapped as a guard.
    pub const EXECUTOR_WORKERS: Region =
        Region::new("executive executor workers", DMA_GRAPH_SLOTS.end(), TABLE_SPAN);

    /// One [`DYNAMIC_RUNTIME_STRIDE`] per dynamically admitted process. Nothing follows it
    /// below [`DISPLAY_WINDOW`], so the process limit can rise to the badge limit in place.
    pub const DYNAMIC_RUNTIME: Region = Region::new(
        "dynamic process runtime windows",
        0x0000_0107_0000_0000,
        (HOSTED_PROCESS_LIMIT - STATIC_PROCESS_COUNT) as u64 * DYNAMIC_RUNTIME_STRIDE,
    );

    /// The root's window onto the display adapter's memory BAR, in a PML4 branch of its own.
    pub const DISPLAY_WINDOW: Region =
        Region::new("display BAR window", 0x0000_0200_0000_0000, 512 * GIB);
    /// Leased spans for retained device and firmware memory.
    pub const DEVICE_MAPPINGS: Region =
        Region::new("device mappings", 0x0000_4000_0000_0000, 4 * GIB);
    /// Process and thread object bodies, in a PML4 branch of their own.
    pub const PS_OBJECTS: Region = Region::new(
        "process and thread objects",
        0x0000_4080_0000_0000,
        512 * GIB,
    );

    /// Every band of the root VSpace, in ascending order.
    pub const REGIONS: &[Region] = &[
        FIXED_LOW,
        FILE_POOL,
        HEAP,
        PROVIDER_LARGE_POOL,
        PROVIDER_BULK_ARENA,
        PE_SCRATCH,
        WIN32K_STACK_ALIASES,
        WIN32K_SESSION_VIEWS,
        DRIVER_HOST_VIEWS,
        DIAGNOSTIC_ALIASES,
        DRIVER_WORKER_ALIASES,
        CONTIGUOUS_RAM_APERTURE,
        WORKER_MIRRORS,
        STATIC_SCRATCH,
        SHELL_MIRRORS,
        DMA_GRAPH_SLOTS,
        EXECUTOR_WORKERS,
        DYNAMIC_RUNTIME,
        DISPLAY_WINDOW,
        DEVICE_MAPPINGS,
        PS_OBJECTS,
    ];

    const _: () = assert!(is_ascending(REGIONS));
    const _: () =
        assert!(HEAP.base.is_multiple_of(TABLE_SPAN) && HEAP.len.is_multiple_of(TABLE_SPAN));
    // The heap's page tables are built at boot into the page directory the image already has;
    // the root does not build another directory before its heap exists.
    const _: () = assert!(HEAP.base / GIB == FIXED_LOW.base / GIB);
    const _: () = assert!((HEAP.end() - 1) / GIB == FIXED_LOW.base / GIB);
    const _: () = assert!(STATIC_SCRATCH.base.is_multiple_of(TABLE_SPAN));
    const _: () = assert!(DYNAMIC_RUNTIME.base.is_multiple_of(TABLE_SPAN));
    const _: () = assert!(HOSTED_PROCESS_LIMIT > STATIC_PROCESS_COUNT);
    // Every lane of every process has a mirror, whichever lanes keep legacy addresses.
    const _: () = assert!(
        (HOSTED_PROCESS_LIMIT * WORKER_LANES_PER_PROCESS) as u64 * WORKER_MIRROR_STRIDE
            <= WORKER_MIRRORS.len
    );
}

/// Bands of a spawned executive-image component's VSpace that are placed against its heap.
pub mod component {
    use super::*;

    /// Windows a driver host maps device resources into, one page table each.
    pub const RESOURCE_WINDOWS: Region =
        Region::spanning("device resource windows", 0x0000_0100_1600_0000, HEAP_BASE);
    /// The most a component heap may occupy.
    pub const HEAP: Region = Region::new(
        "component heap",
        HEAP_BASE,
        COMPONENT_HEAP_MAX_FRAMES * PAGE,
    );
    /// Provider views of section objects.
    pub const SECTION_VIEWS: Region =
        Region::spanning("provider section views", HEAP.end(), 0x0000_0100_3000_0000);

    /// The heap and its neighbours, in ascending order.
    pub const REGIONS: &[Region] = &[RESOURCE_WINDOWS, HEAP, SECTION_VIEWS];

    const _: () = assert!(is_ascending(REGIONS));
    const _: () = assert!(RESOURCE_WINDOWS.base.is_multiple_of(TABLE_SPAN));
    const _: () = assert!(SECTION_VIEWS.base.is_multiple_of(TABLE_SPAN));
}
