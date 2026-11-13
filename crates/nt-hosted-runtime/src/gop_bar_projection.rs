/// A scanout grant derived from one live PCI display BAR and the Simpleboot GOP record.
/// Callers must select a unique display BAR from the current PCI inventory before constructing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GopPciBarAuthority {
    bus: u8,
    device: u8,
    function: u8,
    bar_index: u8,
    bar_start: u64,
    bar_frames: u64,
    scanout_start: u64,
    scanout_bytes: u64,
    inventory_generation: u64,
    provider_domain_id: u64,
    provider_domain_cookie: u64,
    provider_publication: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GopBarProjection {
    first_bar_frame: u64,
    frame_count: u64,
    page_offset: u64,
}

/// An exact read of VGA input-status-1 by the generation that owns the mapped GOP scanout.
/// The I/O decode bit and VGA-compatible subclass come from the selected live PCI function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GopLegacyVgaPortAuthority {
    bar: GopPciBarAuthority,
}

impl GopLegacyVgaPortAuthority {
    pub const fn new(bar: GopPciBarAuthority, pci_class: u32, pci_command: u16,
        scanout_mapped: bool) -> Option<Self> {
        if pci_class >> 8 != 0x03_00 || pci_command & 1 == 0 || !scanout_mapped {
            return None;
        }
        Some(Self { bar })
    }

    pub const fn admit_read8(self, port: u16, inventory_generation: u64,
        domain_id: u64, domain_cookie: u64, provider_publication: u64) -> bool {
        port == 0x3da
            && self.bar.inventory_generation == inventory_generation
            && self.bar.provider_domain_id == domain_id
            && self.bar.provider_domain_cookie == domain_cookie
            && self.bar.provider_publication == provider_publication
    }
}

impl GopBarProjection {
    pub const fn first_bar_frame(self) -> u64 { self.first_bar_frame }
    pub const fn frame_count(self) -> u64 { self.frame_count }
    pub const fn page_offset(self) -> u64 { self.page_offset }
}

impl GopPciBarAuthority {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(bus: u8, device: u8, function: u8, bar_index: u8,
        bar_start: u64, bar_frames: u64, scanout_start: u64, scanout_bytes: u64,
        inventory_generation: u64, provider_domain_id: u64, provider_domain_cookie: u64,
        provider_publication: u64) -> Option<Self> {
        if device > 31 || function > 7 || bar_index > 5 || bar_start == 0
            || bar_start & 0xfff != 0 || bar_frames == 0 || scanout_bytes == 0
            || scanout_start & 0xfff != 0 || scanout_bytes & 0xfff != 0
            || inventory_generation == 0 || provider_domain_id == 0
            || provider_domain_cookie == 0 || provider_publication == 0 {
            return None;
        }
        let Some(bar_bytes) = bar_frames.checked_mul(0x1000) else { return None; };
        let Some(bar_end) = bar_start.checked_add(bar_bytes) else { return None; };
        let Some(scanout_end) = scanout_start.checked_add(scanout_bytes) else { return None; };
        if scanout_start < bar_start || scanout_end > bar_end { return None; }
        Some(Self { bus, device, function, bar_index, bar_start, bar_frames,
            scanout_start, scanout_bytes, inventory_generation, provider_domain_id,
            provider_domain_cookie, provider_publication })
    }

    pub const fn bar_location(self) -> (u8, u8, u8, u8) {
        (self.bus, self.device, self.function, self.bar_index)
    }

    pub const fn bar_start(self) -> u64 { self.bar_start }
    pub const fn bar_frames(self) -> u64 { self.bar_frames }

    pub const fn project(self, request_start: u64, request_bytes: u64,
        inventory_generation: u64, provider_domain_id: u64, provider_domain_cookie: u64,
        provider_publication: u64) -> Option<GopBarProjection> {
        if inventory_generation != self.inventory_generation
            || provider_domain_id != self.provider_domain_id
            || provider_domain_cookie != self.provider_domain_cookie
            || provider_publication != self.provider_publication
            || request_bytes == 0 { return None; }
        let Some(request_end) = request_start.checked_add(request_bytes) else { return None; };
        let Some(scanout_end) = self.scanout_start.checked_add(self.scanout_bytes) else {
            return None;
        };
        if request_start < self.scanout_start || request_end > scanout_end { return None; }
        let byte_offset = request_start - self.bar_start;
        let page_offset = byte_offset & 0xfff;
        let Some(covered) = page_offset.checked_add(request_bytes) else { return None; };
        let Some(rounded) = covered.checked_add(0xfff) else { return None; };
        let frame_count = rounded >> 12;
        let first_bar_frame = byte_offset >> 12;
        let Some(end_frame) = first_bar_frame.checked_add(frame_count) else { return None; };
        if end_frame > self.bar_frames { return None; }
        Some(GopBarProjection { first_bar_frame, frame_count, page_offset })
    }
}
