//! Correlation wire for one file-less win32k TargetDeviceRelation source IRP.
//! The physical provider lane and exact source/device leases remain the authority.

use crate::win32k_source_irp_ioctl_wire::EventIdentity;

pub const PACKET_BYTES: usize = 136;
pub const TERMINAL_PACKET_BYTES: usize = 128;
pub const STATUS_PENDING: u32 = 0x103;
const KIND: u32 = 2;
const VERSION: u32 = 2;
const TERMINAL_KIND: u32 = 3;
const TERMINAL_VERSION: u32 = 1;
const TOKEN_OFF: usize = 80;
const STATUS_OFF: usize = 88;
const INFORMATION_OFF: usize = 96;
const COMPLETED_OFF: usize = 104;
const IOSB_OFF: usize = 112;
const RELATION_OFF: usize = 120;
const RELATION_GENERATION_OFF: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePnpRequest {
    pub nonce: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub device_object_va: u64,
    pub relation_type: u32,
    pub event: Option<EventIdentity>,
    /// Win32k-owned destination for the terminal IO_STATUS_BLOCK.
    pub iosb_va: u64,
    /// Preallocated win32k-owned DEVICE_RELATIONS destination.
    pub relation_allocation_va: u64,
    pub relation_allocation_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePnpResponse {
    Pending {
        token: u64,
    },
    Inline {
        token: u64,
        status: u32,
        information: u64,
    },
}

/// Terminal result sent to win32k while the origin still owns the source IRP.
/// All addresses are correlation data until the receiving lane validates its
/// retained allocation leases and physical destination identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePnpTerminalHandoff {
    pub nonce: u64,
    pub token: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub iosb_va: u64,
    pub relation_allocation_va: u64,
    pub relation_allocation_generation: u64,
    pub status: u32,
    pub information: u64,
    /// Provider-authenticated PDO projected into the origin's DEVICE_RELATIONS.
    pub pdo_va: u64,
}

pub use crate::source_terminal::TerminalPublication;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePnpTerminalAck {
    pub handoff: SourcePnpTerminalHandoff,
    pub publication: TerminalPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    LengthMismatch,
    Malformed,
}

fn u32_at(packet: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(packet[offset..offset + 4].try_into().unwrap())
}

fn u64_at(packet: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(packet[offset..offset + 8].try_into().unwrap())
}

fn put_u32(packet: &mut [u8], offset: usize, value: u32) {
    packet[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(packet: &mut [u8], offset: usize, value: u64) {
    packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn valid_request(request: SourcePnpRequest) -> bool {
    request.nonce != 0
        && request.source_irp_va != 0
        && request.source_ticket_serial != 0
        && request.native_allocation_generation != 0
        && request.device_object_va != 0
        && request.relation_type == nt_pnp_abi::TARGET_DEVICE_RELATION
        && request.iosb_va != 0
        && request.relation_allocation_va != 0
        && request.relation_allocation_generation != 0
        && request.event.is_none_or(|event| {
            event.local_id != 0 && event.object_slot_plus_one != 0 && event.object_generation != 0
        })
}

pub fn encode_request(request: SourcePnpRequest, packet: &mut [u8]) -> Result<(), WireError> {
    if packet.len() != PACKET_BYTES {
        return Err(WireError::LengthMismatch);
    }
    if !valid_request(request) {
        return Err(WireError::Malformed);
    }
    packet.fill(0);
    put_u32(packet, 0, KIND);
    put_u32(packet, 4, VERSION);
    put_u64(packet, 8, request.nonce);
    put_u64(packet, 16, request.source_irp_va);
    put_u64(packet, 24, request.source_ticket_serial);
    put_u64(packet, 32, request.native_allocation_generation);
    put_u64(packet, 40, request.device_object_va);
    put_u32(packet, 48, request.relation_type);
    if let Some(event) = request.event {
        put_u64(packet, 56, event.local_id);
        put_u64(packet, 64, event.object_slot_plus_one);
        put_u64(packet, 72, event.object_generation);
    }
    put_u64(packet, IOSB_OFF, request.iosb_va);
    put_u64(packet, RELATION_OFF, request.relation_allocation_va);
    put_u64(
        packet,
        RELATION_GENERATION_OFF,
        request.relation_allocation_generation,
    );
    Ok(())
}

fn header(packet: &[u8]) -> Result<SourcePnpRequest, WireError> {
    if packet.len() != PACKET_BYTES {
        return Err(WireError::LengthMismatch);
    }
    if u32_at(packet, 0) != KIND
        || u32_at(packet, 4) != VERSION
        || u32_at(packet, 52) != 0
        || packet[108..IOSB_OFF].iter().any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    let event = match (u64_at(packet, 56), u64_at(packet, 64), u64_at(packet, 72)) {
        (0, 0, 0) => None,
        (local_id, object_slot_plus_one, object_generation) => Some(EventIdentity {
            local_id,
            object_slot_plus_one,
            object_generation,
        }),
    };
    let request = SourcePnpRequest {
        nonce: u64_at(packet, 8),
        source_irp_va: u64_at(packet, 16),
        source_ticket_serial: u64_at(packet, 24),
        native_allocation_generation: u64_at(packet, 32),
        device_object_va: u64_at(packet, 40),
        relation_type: u32_at(packet, 48),
        event,
        iosb_va: u64_at(packet, IOSB_OFF),
        relation_allocation_va: u64_at(packet, RELATION_OFF),
        relation_allocation_generation: u64_at(packet, RELATION_GENERATION_OFF),
    };
    if !valid_request(request) {
        return Err(WireError::Malformed);
    }
    Ok(request)
}

pub fn decode_request(packet: &[u8]) -> Result<SourcePnpRequest, WireError> {
    let request = header(packet)?;
    if u64_at(packet, TOKEN_OFF) != 0
        || u32_at(packet, STATUS_OFF) != 0
        || u32_at(packet, 92) != 0
        || u64_at(packet, INFORMATION_OFF) != 0
        || u32_at(packet, COMPLETED_OFF) != 0
    {
        return Err(WireError::Malformed);
    }
    Ok(request)
}

pub fn publish_pending(packet: &mut [u8], token: u64) -> Result<(), WireError> {
    decode_request(packet)?;
    if token == 0 {
        return Err(WireError::Malformed);
    }
    put_u64(packet, TOKEN_OFF, token);
    put_u32(packet, STATUS_OFF, STATUS_PENDING);
    Ok(())
}

pub fn publish_inline_terminal(
    packet: &mut [u8],
    token: u64,
    status: u32,
    information: u64,
) -> Result<(), WireError> {
    decode_request(packet)?;
    if token == 0
        || status == STATUS_PENDING
        || (status & 0x8000_0000 == 0 && information == 0)
        || (status & 0x8000_0000 != 0 && information != 0)
    {
        return Err(WireError::Malformed);
    }
    put_u64(packet, TOKEN_OFF, token);
    put_u32(packet, STATUS_OFF, status);
    put_u64(packet, INFORMATION_OFF, information);
    put_u32(packet, COMPLETED_OFF, 1);
    Ok(())
}

pub fn decode_response(packet: &[u8]) -> Result<SourcePnpResponse, WireError> {
    header(packet)?;
    let token = u64_at(packet, TOKEN_OFF);
    let status = u32_at(packet, STATUS_OFF);
    let information = u64_at(packet, INFORMATION_OFF);
    if token == 0 || u32_at(packet, 92) != 0 {
        return Err(WireError::Malformed);
    }
    match u32_at(packet, COMPLETED_OFF) {
        0 if status == STATUS_PENDING && information == 0 => {
            Ok(SourcePnpResponse::Pending { token })
        }
        1 if status != STATUS_PENDING
            && ((status & 0x8000_0000 == 0 && information != 0)
                || (status & 0x8000_0000 != 0 && information == 0)) =>
        {
            Ok(SourcePnpResponse::Inline {
                token,
                status,
                information,
            })
        }
        _ => Err(WireError::Malformed),
    }
}

fn valid_terminal(handoff: SourcePnpTerminalHandoff) -> bool {
    handoff.nonce != 0
        && handoff.token != 0
        && handoff.source_irp_va != 0
        && handoff.source_ticket_serial != 0
        && handoff.native_allocation_generation != 0
        && handoff.iosb_va != 0
        && handoff.relation_allocation_va != 0
        && handoff.relation_allocation_generation != 0
        && handoff.status != STATUS_PENDING
        && if handoff.status & 0x8000_0000 == 0 {
            handoff.information == handoff.relation_allocation_va && handoff.pdo_va != 0
        } else {
            handoff.information == 0 && handoff.pdo_va == 0
        }
}

pub fn encode_terminal_handoff(
    handoff: SourcePnpTerminalHandoff,
    packet: &mut [u8],
) -> Result<(), WireError> {
    if packet.len() != TERMINAL_PACKET_BYTES {
        return Err(WireError::LengthMismatch);
    }
    if !valid_terminal(handoff) {
        return Err(WireError::Malformed);
    }
    packet.fill(0);
    put_u32(packet, 0, TERMINAL_KIND);
    put_u32(packet, 4, TERMINAL_VERSION);
    put_u64(packet, 8, handoff.nonce);
    put_u64(packet, 16, handoff.token);
    put_u64(packet, 24, handoff.source_irp_va);
    put_u64(packet, 32, handoff.source_ticket_serial);
    put_u64(packet, 40, handoff.native_allocation_generation);
    put_u64(packet, 48, handoff.iosb_va);
    put_u64(packet, 56, handoff.relation_allocation_va);
    put_u64(packet, 64, handoff.relation_allocation_generation);
    put_u32(packet, 72, handoff.status);
    put_u64(packet, 80, handoff.information);
    put_u64(packet, 88, handoff.pdo_va);
    Ok(())
}

fn terminal_header(packet: &[u8]) -> Result<SourcePnpTerminalHandoff, WireError> {
    if packet.len() != TERMINAL_PACKET_BYTES {
        return Err(WireError::LengthMismatch);
    }
    if (u64_at(packet, 104) != 0 && !matches!(u32_at(packet, 96), 3 | 4))
        || u32_at(packet, 0) != TERMINAL_KIND
        || u32_at(packet, 4) != TERMINAL_VERSION
        || u32_at(packet, 76) != 0
        || packet[112..].iter().any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    let handoff = SourcePnpTerminalHandoff {
        nonce: u64_at(packet, 8),
        token: u64_at(packet, 16),
        source_irp_va: u64_at(packet, 24),
        source_ticket_serial: u64_at(packet, 32),
        native_allocation_generation: u64_at(packet, 40),
        iosb_va: u64_at(packet, 48),
        relation_allocation_va: u64_at(packet, 56),
        relation_allocation_generation: u64_at(packet, 64),
        status: u32_at(packet, 72),
        information: u64_at(packet, 80),
        pdo_va: u64_at(packet, 88),
    };
    if !valid_terminal(handoff) {
        return Err(WireError::Malformed);
    }
    Ok(handoff)
}

pub fn decode_terminal_handoff(packet: &[u8]) -> Result<SourcePnpTerminalHandoff, WireError> {
    let handoff = terminal_header(packet)?;
    if u32_at(packet, 96) != 0 || u32_at(packet, 100) != 0 {
        return Err(WireError::Malformed);
    }
    Ok(handoff)
}

pub fn terminal_matches_request(
    request: SourcePnpRequest,
    handoff: SourcePnpTerminalHandoff,
) -> bool {
    request.nonce == handoff.nonce
        && request.source_irp_va == handoff.source_irp_va
        && request.source_ticket_serial == handoff.source_ticket_serial
        && request.native_allocation_generation == handoff.native_allocation_generation
        && request.iosb_va == handoff.iosb_va
        && request.relation_allocation_va == handoff.relation_allocation_va
        && request.relation_allocation_generation == handoff.relation_allocation_generation
}

/// The origin publishes this only after it has durably written the terminal
/// source IRP, IOSB, relation buffer, and any Event signal. A failed or missing
/// acknowledgement leaves the provider completion indeterminate.

/// A canonical deferred Set reserves this sequence before the origin retires its IRP.
pub fn request_terminal_commit(packet: &mut [u8], signal_sequence: u64) -> Result<(), WireError> {
    publish_terminal_ack(packet, TerminalPublication::CommitRequested)?;
    put_u64(packet, 104, signal_sequence);
    Ok(())
}

pub fn terminal_signal_sequence(packet: &[u8]) -> Result<u64, WireError> {
    terminal_header(packet)?;
    Ok(u64_at(packet, 104))
}

pub fn publish_terminal_ack(
    packet: &mut [u8],
    publication: TerminalPublication,
) -> Result<(), WireError> {
    terminal_header(packet)?;
    let previous = match (u32_at(packet, 96), u32_at(packet, 100)) {
        (0, 0) => None,
        (stage, status) => {
            Some(TerminalPublication::decode(stage, status).ok_or(WireError::Malformed)?)
        }
    };
    if !publication.can_follow(previous) {
        return Err(WireError::Malformed);
    }
    let (stage, status) = publication.words();
    put_u32(packet, 96, stage);
    put_u32(packet, 100, status);
    Ok(())
}

pub fn decode_terminal_ack(packet: &[u8]) -> Result<SourcePnpTerminalAck, WireError> {
    let handoff = terminal_header(packet)?;
    let publication = TerminalPublication::decode(u32_at(packet, 96), u32_at(packet, 100))
        .ok_or(WireError::Malformed)?;
    Ok(SourcePnpTerminalAck {
        handoff,
        publication,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SourcePnpRequest {
        SourcePnpRequest {
            nonce: 1,
            source_irp_va: 0x1000,
            source_ticket_serial: 2,
            native_allocation_generation: 3,
            device_object_va: 0x2000,
            relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
            event: Some(EventIdentity {
                local_id: 4,
                object_slot_plus_one: 5,
                object_generation: 6,
            }),
            iosb_va: 0x3000,
            relation_allocation_va: 0x4000,
            relation_allocation_generation: 7,
        }
    }

    fn terminal() -> SourcePnpTerminalHandoff {
        SourcePnpTerminalHandoff {
            nonce: 1,
            token: 8,
            source_irp_va: 0x1000,
            source_ticket_serial: 2,
            native_allocation_generation: 3,
            iosb_va: 0x3000,
            relation_allocation_va: 0x4000,
            relation_allocation_generation: 7,
            status: 0,
            information: 0x4000,
            pdo_va: 0x5000,
        }
    }

    #[test]
    fn prepare_commit_and_stopped_discard_do_not_skip_or_replay_phases() {
        let handoff = terminal();
        let mut packet = [0; TERMINAL_PACKET_BYTES];
        encode_terminal_handoff(handoff, &mut packet).unwrap();
        assert!(publish_terminal_ack(&mut packet, TerminalPublication::Committed).is_err());
        publish_terminal_ack(&mut packet, TerminalPublication::Published).unwrap();
        assert!(publish_terminal_ack(&mut packet, TerminalPublication::Published).is_err());
        request_terminal_commit(&mut packet, 41).unwrap();
        assert_eq!(terminal_signal_sequence(&packet), Ok(41));
        assert_eq!(decode_terminal_ack(&packet).unwrap().handoff, handoff);
        publish_terminal_ack(&mut packet, TerminalPublication::Committed).unwrap();
        assert_eq!(terminal_signal_sequence(&packet), Ok(41));
        assert_eq!(
            decode_terminal_ack(&packet).unwrap().publication,
            TerminalPublication::Committed
        );
        assert!(publish_terminal_ack(&mut packet, TerminalPublication::Committed).is_err());
        encode_terminal_handoff(handoff, &mut packet).unwrap();
        publish_terminal_ack(&mut packet, TerminalPublication::DiscardRequested).unwrap();
        publish_terminal_ack(&mut packet, TerminalPublication::Discarded).unwrap();
        assert_eq!(
            decode_terminal_ack(&packet).unwrap().publication,
            TerminalPublication::Discarded
        );
    }

    #[test]
    fn request_and_retained_terminal_round_trip() {
        let mut packet = [0; PACKET_BYTES];
        encode_request(request(), &mut packet).unwrap();
        assert_eq!(decode_request(&packet), Ok(request()));
        publish_inline_terminal(&mut packet, 7, 0, 0x3000).unwrap();
        assert_eq!(
            decode_response(&packet),
            Ok(SourcePnpResponse::Inline {
                token: 7,
                status: 0,
                information: 0x3000,
            })
        );
    }

    #[test]
    fn pending_requires_token_and_zero_information() {
        let mut packet = [0; PACKET_BYTES];
        encode_request(request(), &mut packet).unwrap();
        publish_pending(&mut packet, 8).unwrap();
        assert_eq!(
            decode_response(&packet),
            Ok(SourcePnpResponse::Pending { token: 8 })
        );
        packet[INFORMATION_OFF] = 1;
        assert_eq!(decode_response(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn rejects_unowned_success_and_forged_identity() {
        let mut packet = [0; PACKET_BYTES];
        encode_request(request(), &mut packet).unwrap();
        assert_eq!(
            publish_inline_terminal(&mut packet, 9, 0, 0),
            Err(WireError::Malformed)
        );
        packet[24..32].fill(0);
        assert_eq!(decode_request(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn request_requires_origin_owned_destinations() {
        let mut packet = [0; PACKET_BYTES];
        let mut missing = request();
        missing.iosb_va = 0;
        assert_eq!(
            encode_request(missing, &mut packet),
            Err(WireError::Malformed)
        );
        missing = request();
        missing.relation_allocation_generation = 0;
        assert_eq!(
            encode_request(missing, &mut packet),
            Err(WireError::Malformed)
        );
        encode_request(request(), &mut packet).unwrap();
        packet[RELATION_OFF..RELATION_OFF + 8].fill(0);
        assert_eq!(decode_request(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn terminal_handoff_and_exact_ack_round_trip() {
        let mut packet = [0; TERMINAL_PACKET_BYTES];
        encode_terminal_handoff(terminal(), &mut packet).unwrap();
        assert_eq!(decode_terminal_handoff(&packet), Ok(terminal()));
        assert!(terminal_matches_request(request(), terminal()));
        publish_terminal_ack(&mut packet, TerminalPublication::Published).unwrap();
        assert_eq!(
            decode_terminal_ack(&packet),
            Ok(SourcePnpTerminalAck {
                handoff: terminal(),
                publication: TerminalPublication::Published,
            })
        );
        assert_eq!(decode_terminal_handoff(&packet), Err(WireError::Malformed));
        assert_eq!(
            publish_terminal_ack(&mut packet, TerminalPublication::Published),
            Err(WireError::Malformed)
        );
    }

    #[test]
    fn terminal_rejects_wrong_destination_and_unbound_ack() {
        let mut packet = [0; TERMINAL_PACKET_BYTES];
        let mut handoff = terminal();
        handoff.information = 0x5000;
        assert_eq!(
            encode_terminal_handoff(handoff, &mut packet),
            Err(WireError::Malformed)
        );
        handoff = terminal();
        handoff.relation_allocation_generation += 1;
        assert!(!terminal_matches_request(request(), handoff));
        encode_terminal_handoff(terminal(), &mut packet).unwrap();
        assert_eq!(
            publish_terminal_ack(&mut packet, TerminalPublication::Failed(0)),
            Err(WireError::Malformed)
        );
        packet[56] ^= 1;
        assert_eq!(decode_terminal_handoff(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn failed_terminal_and_publication_failure_are_distinct() {
        let mut packet = [0; TERMINAL_PACKET_BYTES];
        let mut handoff = terminal();
        handoff.status = 0xc000_000d;
        handoff.information = 0;
        handoff.pdo_va = 0;
        encode_terminal_handoff(handoff, &mut packet).unwrap();
        publish_terminal_ack(&mut packet, TerminalPublication::Failed(0xc000_0001)).unwrap();
        assert_eq!(
            decode_terminal_ack(&packet),
            Ok(SourcePnpTerminalAck {
                handoff,
                publication: TerminalPublication::Failed(0xc000_0001),
            })
        );
    }
}
