//! NT5 x64 CREATE security graph projected into one provider address space.
//!
//! The source ticket is an equality proof, not a pointer translation. Token addresses in this
//! graph must refer to provider-local projections backed by retained canonical token references.
//! The native adapter validates those references before calling this ABI encoder.

use crate::{
    security_client_x64::{Luid, SecurityQualityOfService},
    GuestAddr, UnicodeString,
};
use bytemuck::{Pod, Zeroable};
use core::mem::{offset_of, size_of};

pub const IO_SECURITY_CONTEXT_SIZE: usize = 0x18;
pub const SECURITY_SUBJECT_CONTEXT_SIZE: usize = 0x20;
pub const ACCESS_STATE_SIZE: usize = 0xa0;
pub const CREATE_SECURITY_GRAPH_SIZE: usize = 0xc8;
pub const ACCESS_STATE_OFFSET: usize = IO_SECURITY_CONTEXT_SIZE;
pub const SECURITY_QOS_OFFSET: usize = IO_SECURITY_CONTEXT_SIZE + ACCESS_STATE_SIZE;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoSecurityContext {
    pub security_qos: GuestAddr,
    pub access_state: GuestAddr,
    pub desired_access: u32,
    pub full_create_options: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct SecuritySubjectContext {
    pub client_token: GuestAddr,
    pub impersonation_level: u32,
    _alignment: u32,
    pub primary_token: GuestAddr,
    pub process_audit_id: GuestAddr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct LuidAndAttributes {
    pub luid: Luid,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct InitialPrivilegeSet {
    pub privilege_count: u32,
    pub control: u32,
    pub privileges: [LuidAndAttributes; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct AccessState {
    pub operation_id: Luid,
    pub security_evaluated: u8,
    pub generate_audit: u8,
    pub generate_on_close: u8,
    pub privileges_allocated: u8,
    pub flags: u32,
    pub remaining_desired_access: u32,
    pub previously_granted_access: u32,
    pub original_desired_access: u32,
    _subject_alignment: u32,
    pub subject_security_context: SecuritySubjectContext,
    pub security_descriptor: GuestAddr,
    pub aux_data: GuestAddr,
    pub privileges: InitialPrivilegeSet,
    pub audit_privileges: u8,
    _name_alignment: [u8; 3],
    pub object_name: UnicodeString,
    pub object_type_name: UnicodeString,
}

/// Initial access state for a CREATE before access checks change the remaining or granted mask.
pub fn initial_create_access_state(desired_access: u32) -> AccessState {
    AccessState {
        remaining_desired_access: desired_access,
        original_desired_access: desired_access,
        ..AccessState::default()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct CreateSecurityGraph {
    pub io: IoSecurityContext,
    pub access: AccessState,
    pub qos: SecurityQualityOfService,
    _tail_alignment: [u8; 4],
}

const _: () = {
    assert!(size_of::<IoSecurityContext>() == IO_SECURITY_CONTEXT_SIZE);
    assert!(offset_of!(IoSecurityContext, access_state) == 0x08);
    assert!(offset_of!(IoSecurityContext, desired_access) == 0x10);
    assert!(offset_of!(IoSecurityContext, full_create_options) == 0x14);
    assert!(size_of::<SecuritySubjectContext>() == SECURITY_SUBJECT_CONTEXT_SIZE);
    assert!(offset_of!(SecuritySubjectContext, impersonation_level) == 0x08);
    assert!(offset_of!(SecuritySubjectContext, primary_token) == 0x10);
    assert!(offset_of!(SecuritySubjectContext, process_audit_id) == 0x18);
    assert!(size_of::<LuidAndAttributes>() == 0x0c);
    assert!(size_of::<InitialPrivilegeSet>() == 0x2c);
    assert!(size_of::<AccessState>() == ACCESS_STATE_SIZE);
    assert!(offset_of!(AccessState, subject_security_context) == 0x20);
    assert!(offset_of!(AccessState, security_descriptor) == 0x40);
    assert!(offset_of!(AccessState, aux_data) == 0x48);
    assert!(offset_of!(AccessState, privileges) == 0x50);
    assert!(offset_of!(AccessState, audit_privileges) == 0x7c);
    assert!(offset_of!(AccessState, object_name) == 0x80);
    assert!(offset_of!(AccessState, object_type_name) == 0x90);
    assert!(size_of::<CreateSecurityGraph>() == CREATE_SECURITY_GRAPH_SIZE);
    assert!(offset_of!(CreateSecurityGraph, access) == ACCESS_STATE_OFFSET);
    assert!(offset_of!(CreateSecurityGraph, qos) == SECURITY_QOS_OFFSET);
};

/// Exact source owner identity supplied from a retained canonical source CREATE. The address is
/// compared only against the source's local IO_SECURITY_CONTEXT; it is never placed in the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSecurityProof {
    pub ticket_id: u64,
    pub ticket_generation: u64,
    pub irp_id: u64,
    pub irp_generation: u64,
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub security_context_address: u64,
    pub primary_token_id: u64,
    pub primary_token_generation: u64,
    pub client_token_id: u64,
    pub client_token_generation: u64,
}

impl SourceSecurityProof {
    fn valid(self) -> bool {
        self.ticket_id != 0
            && self.ticket_generation != 0
            && self.irp_id != 0
            && self.irp_generation != 0
            && self.domain_id != 0
            && self.domain_cookie != 0
            && self.security_context_address != 0
            && self.primary_token_id != 0
            && self.primary_token_generation != 0
            && (self.client_token_id == 0) == (self.client_token_generation == 0)
    }
}

/// Provider-local token object projection, checked by the native adapter against a retained
/// canonical token reference. Neither the canonical token id nor its generation is a guest pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderTokenProjection {
    pub address: GuestAddr,
    pub token_id: u64,
    pub token_generation: u64,
    pub domain_id: u64,
    pub domain_cookie: u64,
}

impl ProviderTokenProjection {
    fn valid_for(self, domain_id: u64, domain_cookie: u64) -> bool {
        !self.address.is_null()
            && self.token_id != 0
            && self.token_generation != 0
            && self.domain_id == domain_id
            && self.domain_cookie == domain_cookie
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessStateFields {
    pub operation_id: Luid,
    pub security_evaluated: bool,
    pub generate_audit: bool,
    pub generate_on_close: bool,
    pub flags: u32,
    pub remaining_desired_access: u32,
    pub previously_granted_access: u32,
    pub original_desired_access: u32,
    pub security_descriptor: GuestAddr,
    pub aux_data: GuestAddr,
    pub privileges: InitialPrivilegeSet,
    pub audit_privileges: bool,
    pub object_name: UnicodeString,
    pub object_type_name: UnicodeString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateQosFields {
    pub length: u32,
    pub impersonation_level: u32,
    pub context_tracking_mode: u8,
    pub effective_only: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateSecurityFields {
    pub source: SourceSecurityProof,
    pub provider_domain_id: u64,
    pub provider_domain_cookie: u64,
    pub primary_token: ProviderTokenProjection,
    pub client_token: Option<(ProviderTokenProjection, u32)>,
    pub process_audit_id: GuestAddr,
    pub desired_access: u32,
    pub full_create_options: u32,
    pub qos: Option<CreateQosFields>,
    pub access: AccessStateFields,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateSecurityEncodingError {
    BufferTooSmall,
    InvalidSource,
    InvalidProviderAddress,
    InvalidTokenProjection,
    InvalidAccessState,
    InvalidQos,
}

/// Capture scalar ACCESS_STATE data without carrying source-domain pointers into a provider.
/// Pointer-bearing fields need separately owned, provider-local projections before admission.
pub fn capture_pointer_free_access_state(
    source: AccessState,
) -> Result<AccessStateFields, CreateSecurityEncodingError> {
    if source.security_evaluated > 1
        || source.generate_audit > 1
        || source.generate_on_close > 1
        || source.privileges_allocated != 0
        || source.audit_privileges > 1
        || source.privileges.privilege_count > 3
        || !source.security_descriptor.is_null()
        || !source.aux_data.is_null()
        || source.object_name != UnicodeString::default()
        || source.object_type_name != UnicodeString::default()
    {
        return Err(CreateSecurityEncodingError::InvalidAccessState);
    }
    Ok(AccessStateFields {
        operation_id: source.operation_id,
        security_evaluated: source.security_evaluated != 0,
        generate_audit: source.generate_audit != 0,
        generate_on_close: source.generate_on_close != 0,
        flags: source.flags,
        remaining_desired_access: source.remaining_desired_access,
        previously_granted_access: source.previously_granted_access,
        original_desired_access: source.original_desired_access,
        security_descriptor: GuestAddr::NULL,
        aux_data: GuestAddr::NULL,
        privileges: source.privileges,
        audit_privileges: source.audit_privileges != 0,
        object_name: UnicodeString::default(),
        object_type_name: UnicodeString::default(),
    })
}

pub fn capture_create_qos(
    source: SecurityQualityOfService,
) -> Result<CreateQosFields, CreateSecurityEncodingError> {
    if source.length != size_of::<SecurityQualityOfService>() as u32
        || source.impersonation_level > 3
        || source.context_tracking_mode > 1
        || source.effective_only > 1
    {
        return Err(CreateSecurityEncodingError::InvalidQos);
    }
    Ok(CreateQosFields {
        length: source.length,
        impersonation_level: source.impersonation_level,
        context_tracking_mode: source.context_tracking_mode,
        effective_only: source.effective_only,
    })
}

fn valid_unicode(value: UnicodeString) -> bool {
    value.length <= value.maximum_length
        && value.length & 1 == 0
        && value.maximum_length & 1 == 0
        && (value.maximum_length == 0 || !value.buffer.is_null())
}

/// Encode one complete provider-local graph. All validation precedes the write. A native caller
/// must have checked the token projections against its retained canonical token references and
/// copied any non-null descriptor, AuxData, audit, or name buffers into the provider domain.
pub fn encode_create_security_graph(
    base: GuestAddr,
    expected_source: SourceSecurityProof,
    fields: CreateSecurityFields,
    output: &mut [u8],
) -> Result<(), CreateSecurityEncodingError> {
    if output.len() < CREATE_SECURITY_GRAPH_SIZE {
        return Err(CreateSecurityEncodingError::BufferTooSmall);
    }
    if !expected_source.valid() || fields.source != expected_source {
        return Err(CreateSecurityEncodingError::InvalidSource);
    }
    if base.is_null()
        || base.0 & 7 != 0
        || base
            .0
            .checked_add(CREATE_SECURITY_GRAPH_SIZE as u64)
            .is_none()
        || fields.provider_domain_id == 0
        || fields.provider_domain_cookie == 0
    {
        return Err(CreateSecurityEncodingError::InvalidProviderAddress);
    }
    if !fields
        .primary_token
        .valid_for(fields.provider_domain_id, fields.provider_domain_cookie)
        || fields.primary_token.token_id != expected_source.primary_token_id
        || fields.primary_token.token_generation != expected_source.primary_token_generation
        || fields.client_token.is_some_and(|(client, level)| {
            !client.valid_for(fields.provider_domain_id, fields.provider_domain_cookie) || level > 3
        })
        || match fields.client_token {
            Some((client, _)) => {
                client.token_id != expected_source.client_token_id
                    || client.token_generation != expected_source.client_token_generation
            }
            None => expected_source.client_token_id != 0,
        }
    {
        return Err(CreateSecurityEncodingError::InvalidTokenProjection);
    }
    if fields.access.privileges.privilege_count > 3
        || !valid_unicode(fields.access.object_name)
        || !valid_unicode(fields.access.object_type_name)
    {
        return Err(CreateSecurityEncodingError::InvalidAccessState);
    }
    if fields.qos.is_some_and(|qos| {
        qos.length != size_of::<SecurityQualityOfService>() as u32
            || qos.impersonation_level > 3
            || qos.context_tracking_mode > 1
            || qos.effective_only > 1
    }) {
        return Err(CreateSecurityEncodingError::InvalidQos);
    }
    let mut qos = SecurityQualityOfService::default();
    if let Some(fields) = fields.qos {
        qos.length = fields.length;
        qos.impersonation_level = fields.impersonation_level;
        qos.context_tracking_mode = fields.context_tracking_mode;
        qos.effective_only = fields.effective_only;
    }
    let graph = CreateSecurityGraph {
        io: IoSecurityContext {
            security_qos: fields.qos.map_or(GuestAddr::NULL, |_| {
                GuestAddr(base.0 + SECURITY_QOS_OFFSET as u64)
            }),
            access_state: GuestAddr(base.0 + ACCESS_STATE_OFFSET as u64),
            desired_access: fields.desired_access,
            full_create_options: fields.full_create_options,
        },
        access: AccessState {
            operation_id: fields.access.operation_id,
            security_evaluated: u8::from(fields.access.security_evaluated),
            generate_audit: u8::from(fields.access.generate_audit),
            generate_on_close: u8::from(fields.access.generate_on_close),
            privileges_allocated: 0,
            flags: fields.access.flags,
            remaining_desired_access: fields.access.remaining_desired_access,
            previously_granted_access: fields.access.previously_granted_access,
            original_desired_access: fields.access.original_desired_access,
            _subject_alignment: 0,
            subject_security_context: SecuritySubjectContext {
                client_token: fields
                    .client_token
                    .map_or(GuestAddr::NULL, |(client, _)| client.address),
                impersonation_level: fields.client_token.map_or(0, |(_, level)| level),
                _alignment: 0,
                primary_token: fields.primary_token.address,
                process_audit_id: fields.process_audit_id,
            },
            security_descriptor: fields.access.security_descriptor,
            aux_data: fields.access.aux_data,
            privileges: fields.access.privileges,
            audit_privileges: u8::from(fields.access.audit_privileges),
            _name_alignment: [0; 3],
            object_name: fields.access.object_name,
            object_type_name: fields.access.object_type_name,
        },
        qos,
        _tail_alignment: [0; 4],
    };
    output[..CREATE_SECURITY_GRAPH_SIZE].copy_from_slice(bytemuck::bytes_of(&graph));
    Ok(())
}

#[cfg(test)]
#[path = "security_create_x64_tests.rs"]
mod tests;
