//! Exact x86-64 `mov r64, cr8` decoding and saved-context projection for a hosted #GP.

/// Destination is the x86 GPR number (RAX=0, RCX=1, ..., R15=15).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cr8Read {
    pub register: u8,
    pub len: u8,
}

/// Exact component activation identity published beside the IRQL. The physical lane owner must
/// supply its expected lane ID; a stale activation generation cannot authorize a later fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cr8ActivationIdentity {
    pub lane_id: u64,
    pub lane_generation: u32,
    pub dispatch_id: u64,
    pub activation_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedCr8Irql {
    pub activation: Cr8ActivationIdentity,
    pub irql: u8,
}

impl PublishedCr8Irql {
    pub fn for_activation(self, expected: Cr8ActivationIdentity) -> Option<u8> {
        (self.activation == expected && self.irql <= 15).then_some(self.irql)
    }

    /// The executive knows the physical stack lane and its root-owned request/dispatch ID.
    /// A receipt from a previous use of the same physical lane must not service this fault.
    pub fn for_fault(self, lane_id: u64, dispatch_id: u64) -> Option<u8> {
        (self.activation.lane_id == lane_id
            && self.activation.lane_generation != 0
            && self.activation.activation_generation != 0
            && self.activation.dispatch_id == dispatch_id
            && dispatch_id != 0
            && self.irql <= 15).then_some(self.irql)
    }
}

/// Recognize only the privileged register-to-register CR8 read. Memory forms, writes and reads
/// from other control registers remain ordinary faults. One REX prefix may select CR8 and R8-R15.
pub fn decode_cr8_read(bytes: &[u8]) -> Option<Cr8Read> {
    let rex = *bytes.first()?;
    if !(0x44..=0x4f).contains(&rex) || rex & 0x04 == 0 {
        return None;
    }
    if bytes.get(1..3)? != [0x0f, 0x20] {
        return None;
    }
    let modrm = *bytes.get(3)?;
    if modrm & 0xf8 != 0xc0 {
        return None;
    }
    Some(Cr8Read {
        register: (modrm & 7) + if rex & 1 != 0 { 8 } else { 0 },
        len: 4,
    })
}

/// Project the current activation KIRQL into a stopped seL4 x86-64 20-word register snapshot.
/// Return the selected-write mask so no other register can be installed. Overflow leaves the
/// snapshot unchanged. The caller must validate the exact stopped lane before and after reading.
pub fn project_cr8_read(registers: &mut [u64; 20], read: Cr8Read, irql: u8) -> Option<u64> {
    const GPR_TO_SEL4: [usize; 16] = [3, 5, 6, 4, 1, 9, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17];
    if read.len != 4 || irql > 15 {
        return None;
    }
    let target = *GPR_TO_SEL4.get(read.register as usize)?;
    let next_ip = registers[0].checked_add(read.len as u64)?;
    registers[0] = next_ip;
    registers[target] = u64::from(irql);
    Some((1u64 << 0) | (1u64 << target))
}
