//! Bounded, pointer-free descriptor transfer for win32k object-security assignment.

use nt_object_manager::win32k_ob::{ObHandleTable, ObKind};
use nt_security::{
    assign_object_security_with_audit, CapturedSubjectTokens, GenericMapping,
    ObjectSecurityAssignment, ProcessorMode, SecurityAssignmentAudit, SecurityAssignmentClient,
    SecurityAssignmentInheritance,
};

pub const MAX_DESCRIPTOR_LEN: usize = nt_object_manager::win32k_ob::OB_SECURITY_DESCRIPTOR_MAX;
pub const HEADER_LEN: usize = 32;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentPacket<'a> {
    pub object: u64,
    pub object_type: u64,
    pub access_state: u64,
    pub parent: Option<&'a [u8]>,
    pub creator: Option<&'a [u8]>,
}

impl AssignmentPacket<'_> {
    pub fn encoded_len(&self) -> Result<usize, u32> {
        let parent = self.parent.map_or(0, |bytes| bytes.len());
        let creator = self.creator.map_or(0, |bytes| bytes.len());
        if self.object == 0
            || self.object_type == 0
            || parent > MAX_DESCRIPTOR_LEN
            || creator > MAX_DESCRIPTOR_LEN
            || self.parent.is_some_and(|bytes| bytes.is_empty())
            || self.creator.is_some_and(|bytes| bytes.is_empty())
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        HEADER_LEN
            .checked_add(parent)
            .and_then(|len| len.checked_add(creator))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), u32> {
        let len = self.encoded_len()?;
        if output.len() != len {
            return Err(STATUS_INVALID_PARAMETER);
        }
        output[0..8].copy_from_slice(&self.object.to_le_bytes());
        output[8..16].copy_from_slice(&self.object_type.to_le_bytes());
        output[16..24].copy_from_slice(&self.access_state.to_le_bytes());
        let parent = self.parent.unwrap_or(&[]);
        let creator = self.creator.unwrap_or(&[]);
        output[24..28].copy_from_slice(&(parent.len() as u32).to_le_bytes());
        output[28..32].copy_from_slice(&(creator.len() as u32).to_le_bytes());
        output[HEADER_LEN..HEADER_LEN + parent.len()].copy_from_slice(parent);
        output[HEADER_LEN + parent.len()..].copy_from_slice(creator);
        Ok(())
    }
}

pub fn decode_assignment_packet(bytes: &[u8]) -> Result<AssignmentPacket<'_>, u32> {
    if bytes.len() < HEADER_LEN {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let word = |start| u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap());
    let count = |start| u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize;
    let parent_len = count(24);
    let creator_len = count(28);
    let parent_end = HEADER_LEN
        .checked_add(parent_len)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let end = parent_end
        .checked_add(creator_len)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if parent_len > MAX_DESCRIPTOR_LEN || creator_len > MAX_DESCRIPTOR_LEN || end != bytes.len() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let packet = AssignmentPacket {
        object: word(0),
        object_type: word(8),
        access_state: word(16),
        parent: (parent_len != 0).then_some(&bytes[HEADER_LEN..parent_end]),
        creator: (creator_len != 0).then_some(&bytes[parent_end..end]),
    };
    packet.encoded_len()?;
    Ok(packet)
}

/// Evaluate with retained canonical tokens, deliver privilege decisions, then publish to the
/// uniquely owned Desktop body. Neither a failed policy nor an ambiguous body mutates security.
pub fn assign_exact_desktop(
    table: &mut ObHandleTable,
    packet: AssignmentPacket<'_>,
    subject: &CapturedSubjectTokens<'_>,
    mapping: &GenericMapping,
    mode: ProcessorMode,
    deliver_audit: impl FnOnce(SecurityAssignmentAudit),
) -> Result<(), u32> {
    if table.kind_by_body(packet.object) != Some(ObKind::Desktop) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let client = subject.client.as_ref().map(|client| SecurityAssignmentClient {
        token: client.token,
        level: client.level,
    });
    let request = ObjectSecurityAssignment {
        primary: subject.primary,
        client,
        creator: packet.creator,
        parent: packet.parent,
        mapping,
        is_container: false,
        mode,
        object_type: None,
        inheritance: SecurityAssignmentInheritance::Legacy,
    };
    let mut audit = SecurityAssignmentAudit::default();
    let descriptor = assign_object_security_with_audit(&request, &mut audit);
    deliver_audit(audit);
    let descriptor = descriptor?;
    if descriptor.len() > MAX_DESCRIPTOR_LEN {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    if !table.set_security_descriptor_by_body(packet.object, ObKind::Desktop, &descriptor) {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_security::AccessToken;

    #[test]
    fn descriptor_packet_roundtrips_without_pointer_contents() {
        let packet = AssignmentPacket {
            object: 0x1000,
            object_type: 0x2000,
            access_state: 0x3000,
            parent: Some(&[1, 2, 3]),
            creator: Some(&[4, 5]),
        };
        let mut bytes = [0; HEADER_LEN + 5];
        packet.encode(&mut bytes).unwrap();
        assert_eq!(decode_assignment_packet(&bytes), Ok(packet));
    }

    #[test]
    fn descriptor_packet_rejects_truncation_and_oversize() {
        let packet = AssignmentPacket {
            object: 1,
            object_type: 2,
            access_state: 3,
            parent: None,
            creator: None,
        };
        let mut bytes = [0; HEADER_LEN];
        packet.encode(&mut bytes).unwrap();
        assert!(decode_assignment_packet(&bytes[..HEADER_LEN - 1]).is_err());
        bytes[24..28].copy_from_slice(&((MAX_DESCRIPTOR_LEN + 1) as u32).to_le_bytes());
        assert!(decode_assignment_packet(&bytes).is_err());
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_assignment_packet(&bytes).is_err());
    }

    fn mapping() -> GenericMapping {
        GenericMapping {
            generic_read: 0x1,
            generic_write: 0x2,
            generic_execute: 0x4,
            generic_all: 0x7,
        }
    }

    #[test]
    fn assignment_publishes_only_to_exact_pending_desktop() {
        let primary = AccessToken::system();
        let subject = CapturedSubjectTokens {
            primary: &primary,
            client: None,
            process_audit_id: 7,
        };
        let mut table = ObHandleTable::new();
        assert!(table.latch_pending(ObKind::WindowStation, 0x1000));
        assert!(table.latch_pending(ObKind::Desktop, 0x2000));
        let packet = AssignmentPacket {
            object: 0x2000,
            object_type: 0x3000,
            access_state: 0,
            parent: None,
            creator: None,
        };
        let mut audited = false;
        assign_exact_desktop(
            &mut table,
            packet,
            &subject,
            &mapping(),
            ProcessorMode::UserMode,
            |_| audited = true,
        )
        .unwrap();
        assert!(audited);
        assert_eq!(table.security_descriptor_by_body(0x1000), Some((ObKind::WindowStation, None)));
        assert!(table.security_descriptor_by_body(0x2000).unwrap().1.is_some());
        let handle = table.insert_pending(0x2000);
        assert_ne!(handle, 0);
        assert!(table.security_descriptor(handle).is_some());
    }

    #[test]
    fn failed_assignment_preserves_pending_security() {
        let primary = AccessToken::system();
        let subject = CapturedSubjectTokens {
            primary: &primary,
            client: None,
            process_audit_id: 7,
        };
        let mut table = ObHandleTable::new();
        assert!(table.latch_pending_with_security(ObKind::Desktop, 0x2000, Some(&[1, 2])));
        let packet = AssignmentPacket {
            object: 0x2000,
            object_type: 0x3000,
            access_state: 0,
            parent: None,
            creator: Some(&[0xff]),
        };
        let mut audited = false;
        assert!(assign_exact_desktop(
            &mut table,
            packet,
            &subject,
            &mapping(),
            ProcessorMode::UserMode,
            |_| audited = true,
        )
        .is_err());
        assert!(audited);
        assert_eq!(table.security_descriptor_by_body(0x2000), Some((ObKind::Desktop, Some(&[1, 2][..]))));
        assert!(table.latch_pending(ObKind::WindowStation, 0x3000));
        let wrong = AssignmentPacket { object: 0x3000, ..packet };
        assert_eq!(assign_exact_desktop(
            &mut table,
            wrong,
            &subject,
            &mapping(),
            ProcessorMode::UserMode,
            |_| panic!("wrong type must not reach policy"),
        ), Err(STATUS_INVALID_HANDLE));
    }
}
