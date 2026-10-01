//! Exact receipt that the source Call continuation accepted a Pending response.

pub const PACKET_BYTES: usize = 56;
const MAGIC: u32 = 0x4153_4952;
const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingSourceKind { Ioctl = 1, Fsd = 2, Pnp = 3 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingArmedIdentity {
    pub kind: PendingSourceKind,
    pub nonce: u64,
    pub token: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError { Malformed }

fn valid(identity: PendingArmedIdentity) -> bool {
    identity.nonce != 0 && identity.token != 0 && identity.source_irp_va != 0
        && identity.source_ticket_serial != 0 && identity.native_allocation_generation != 0
}

pub fn encode(identity: PendingArmedIdentity, packet: &mut [u8]) -> Result<(), WireError> {
    if packet.len() != PACKET_BYTES || !valid(identity) { return Err(WireError::Malformed); }
    packet[..4].copy_from_slice(&MAGIC.to_le_bytes());
    packet[4..8].copy_from_slice(&VERSION.to_le_bytes());
    for (chunk, value) in packet[8..].chunks_exact_mut(8).zip([
        identity.kind as u64, identity.nonce, identity.token, identity.source_irp_va,
        identity.source_ticket_serial, identity.native_allocation_generation,
    ]) { chunk.copy_from_slice(&value.to_le_bytes()); }
    Ok(())
}

pub fn decode(packet: &[u8]) -> Result<PendingArmedIdentity, WireError> {
    if packet.len() != PACKET_BYTES
        || packet[..4] != MAGIC.to_le_bytes() || packet[4..8] != VERSION.to_le_bytes()
    { return Err(WireError::Malformed); }
    let word = |offset| u64::from_le_bytes(packet[offset..offset + 8].try_into().unwrap());
    let identity = PendingArmedIdentity {
        kind: match word(8) { 1 => PendingSourceKind::Ioctl, 2 => PendingSourceKind::Fsd,
            3 => PendingSourceKind::Pnp, _ => return Err(WireError::Malformed) },
        nonce: word(16), token: word(24), source_irp_va: word(32),
        source_ticket_serial: word(40), native_allocation_generation: word(48),
    };
    valid(identity).then_some(identity).ok_or(WireError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_arming_receipt_preserves_exact_source_identity() {
        let identity = PendingArmedIdentity { kind: PendingSourceKind::Pnp, nonce: 1, token: 2,
            source_irp_va: 3, source_ticket_serial: 4, native_allocation_generation: 5 };
        let mut packet = [0; PACKET_BYTES];
        encode(identity, &mut packet).unwrap();
        assert_eq!(decode(&packet), Ok(identity));
        packet[48] = 6;
        assert_ne!(decode(&packet), Ok(identity));
        packet[8] = 4;
        assert_eq!(decode(&packet), Err(WireError::Malformed));
        assert_eq!(decode(&packet[..PACKET_BYTES - 1]), Err(WireError::Malformed));
        assert!(encode(PendingArmedIdentity { token: 0, ..identity }, &mut packet).is_err());
    }
}
