//! Canonical directory handles and NT x64 enumeration. Access grants use the
//! Object Manager's current access policy; security descriptor admission remains
//! the responsibility of the future native Nt/Zw adapter.

use crate::namespace::ResolvedPath;
use crate::store::ObjectRef;
use crate::{DirectoryBody, ObjectBody, ObjectManager};
use alloc::vec::Vec;
use nt_status::NtStatus;
use nt_types::{
    rights, AccessMask, AccessMode, CaseSensitivity, ClientId, HandleValue, ObjAttrFlags,
    UnicodeString,
};

pub const OBJECT_NAME_EXISTS: NtStatus = NtStatus(0x4000_0000);
pub const MORE_ENTRIES: NtStatus = NtStatus(0x0000_0105);
pub const NO_MORE_ENTRIES: NtStatus = NtStatus(0x8000_001a_u32 as i32);
pub const OBJECT_PATH_SYNTAX_BAD: NtStatus = NtStatus(0xc000_003b_u32 as i32);
const RECORD_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryHandle {
    pub handle: HandleValue,
    pub created: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryQuery {
    pub status: NtStatus,
    pub context: u32,
    pub return_length: u32,
    pub written: u32,
}

fn case(attributes: ObjAttrFlags) -> CaseSensitivity {
    if attributes.contains(ObjAttrFlags::CASE_INSENSITIVE) {
        CaseSensitivity::CaseInsensitive
    } else {
        CaseSensitivity::CaseSensitive
    }
}

impl ObjectManager {
    fn directory_attributes(
        &self,
        client: ClientId,
        attributes: ObjAttrFlags,
        create: bool,
    ) -> Result<(), NtStatus> {
        let allowed = ObjAttrFlags::CASE_INSENSITIVE
            | ObjAttrFlags::INHERIT
            | ObjAttrFlags::KERNEL_HANDLE
            | ObjAttrFlags::OPEN_IF
            | ObjAttrFlags::PERMANENT;
        if attributes.bits() & !allowed.bits() != 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let mode = self.client_mode(client)?;
        if mode == AccessMode::UserMode
            && (attributes.contains(ObjAttrFlags::KERNEL_HANDLE)
                || (create && attributes.contains(ObjAttrFlags::PERMANENT)))
        {
            return Err(NtStatus::ACCESS_DENIED);
        }
        Ok(())
    }

    fn directory_path(
        &self,
        client: ClientId,
        root: Option<HandleValue>,
        name: &UnicodeString,
    ) -> Result<(ObjectRef, Vec<UnicodeString>), NtStatus> {
        let units = name.as_units();
        if units.len() > (u16::MAX as usize / 2) || units.contains(&0) {
            return Err(NtStatus::OBJECT_NAME_INVALID);
        }
        let absolute = units.first() == Some(&92);
        let start = match (root, absolute) {
            (Some(_), true) => return Err(OBJECT_PATH_SYNTAX_BAD),
            (Some(handle), false) => self.reference_by_handle(
                client,
                handle,
                self.directory_type(),
                AccessMask::empty(),
            )?,
            (None, true) => self.root().ok_or(NtStatus::OBJECT_PATH_NOT_FOUND)?,
            (None, false) => return Err(OBJECT_PATH_SYNTAX_BAD),
        };
        let tail = if absolute { &units[1..] } else { units };
        let mut components = Vec::new();
        if !tail.is_empty() {
            for component in tail.split(|unit| *unit == 92) {
                if component.is_empty() {
                    return Err(NtStatus::OBJECT_NAME_INVALID);
                }
                components.push(UnicodeString::from_units(component));
            }
        }
        Ok((start, components))
    }

    /// Create and open atomically. On failure neither a new name nor a handle
    /// remains published. OPEN_IF opens the exact existing directory.
    pub fn create_directory_handle(
        &mut self,
        client: ClientId,
        root: Option<HandleValue>,
        name: &UnicodeString,
        desired: AccessMask,
        attributes: ObjAttrFlags,
    ) -> Result<DirectoryHandle, NtStatus> {
        self.directory_attributes(client, attributes, true)?;
        let ty = self
            .directory_type()
            .ok_or(NtStatus::OBJECT_PATH_NOT_FOUND)?;
        // An empty name without a root denotes a genuinely unnamed object.
        let named = if root.is_none() && name.is_empty() {
            None
        } else {
            let (start, components) = self.directory_path(client, root, name)?;
            match self.resolve_components_from(&start, &components, case(attributes), true, true)? {
                ResolvedPath::Found(existing) => {
                    if !attributes.contains(ObjAttrFlags::OPEN_IF) {
                        return Err(NtStatus::OBJECT_NAME_COLLISION);
                    }
                    if existing.type_id() != ty {
                        return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                    }
                    let handle = self.open(client, &existing, desired, attributes)?;
                    return Ok(DirectoryHandle {
                        handle,
                        created: false,
                    });
                }
                ResolvedPath::Vacant { parent, name } => {
                    // Enumeration adds a UTF-16 terminator to MaximumLength.
                    if name.len() > (u16::MAX as usize - 2) / 2 {
                        return Err(NtStatus::OBJECT_NAME_INVALID);
                    }
                    Some((parent, name))
                }
            }
        };
        let object = self.create_object(ty, ObjectBody::Directory(DirectoryBody::default()))?;
        let handle = self.open(client, &object, desired, attributes)?;
        if let Some((parent, leaf)) = named {
            let inserted = parent.with_body_mut(|body| match body {
                ObjectBody::Directory(directory) => {
                    directory.insert_case(leaf.clone(), object.clone(), case(attributes))
                }
                _ => Err(NtStatus::OBJECT_PATH_NOT_FOUND),
            });
            if let Err(status) = inserted {
                self.close_handle(client, handle)?;
                return Err(status);
            }
            object.set_name(Some(leaf));
            object.set_parent(Some(parent.id()));
        }
        object.set_permanent(attributes.contains(ObjAttrFlags::PERMANENT));
        Ok(DirectoryHandle {
            handle,
            created: true,
        })
    }

    pub fn open_directory_handle(
        &mut self,
        client: ClientId,
        root: Option<HandleValue>,
        name: &UnicodeString,
        desired: AccessMask,
        attributes: ObjAttrFlags,
    ) -> Result<HandleValue, NtStatus> {
        self.directory_attributes(client, attributes, false)?;
        let (start, components) = self.directory_path(client, root, name)?;
        let object = self.lookup_components_from(&start, &components, case(attributes), true)?;
        if Some(object.type_id()) != self.directory_type() {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        self.open(client, &object, desired, attributes)
    }

    /// One coherent enumeration request. The caller's address is used only for
    /// pointer relocation; it is never dereferenced. Admission and insufficient-
    /// buffer failures leave output intact; end-of-enumeration may return a zero
    /// terminator as NT does.
    pub fn query_directory(
        &self,
        client: ClientId,
        handle: HandleValue,
        context: u32,
        restart: bool,
        single: bool,
        output_base: u64,
        output: &mut [u8],
    ) -> Result<DirectoryQuery, NtStatus> {
        if output.len() > u32::MAX as usize {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        output_base
            .checked_add(output.len() as u64)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let object = self.reference_by_handle(
            client,
            handle,
            self.directory_type(),
            rights::directory::QUERY,
        )?;
        let start = if restart { 0 } else { context };
        object.with_body(|body| {
            let ObjectBody::Directory(directory) = body else {
                return Err(NtStatus::OBJECT_TYPE_MISMATCH);
            };
            let mut entries = Vec::new();
            let mut total = RECORD_SIZE;
            let mut status = NO_MORE_ENTRIES;
            for (name, child) in directory.children().skip(start as usize) {
                let ty = self
                    .object_type(child.type_id())
                    .ok_or(NtStatus::OBJECT_TYPE_MISMATCH)?;
                let type_name = UnicodeString::from_str(ty.name());
                let name_len = name
                    .len()
                    .checked_mul(2)
                    .ok_or(NtStatus::INVALID_PARAMETER)?;
                let type_len = type_name
                    .len()
                    .checked_mul(2)
                    .ok_or(NtStatus::INVALID_PARAMETER)?;
                if name_len > u16::MAX as usize - 2 || type_len > u16::MAX as usize - 2 {
                    return Err(NtStatus::OBJECT_NAME_INVALID);
                }
                let needed = RECORD_SIZE
                    .checked_add(name_len)
                    .and_then(|n| n.checked_add(type_len))
                    .and_then(|n| n.checked_add(4))
                    .ok_or(NtStatus::INVALID_PARAMETER)?;
                let next_total = total
                    .checked_add(needed)
                    .ok_or(NtStatus::INVALID_PARAMETER)?;
                if next_total > output.len() {
                    status = if single {
                        total = next_total;
                        NtStatus::BUFFER_TOO_SMALL
                    } else {
                        MORE_ENTRIES
                    };
                    break;
                }
                total = next_total;
                entries.push((name, type_name));
                status = NtStatus::SUCCESS;
                if single {
                    break;
                }
            }
            let return_length = u32::try_from(total).map_err(|_| NtStatus::INVALID_PARAMETER)?;
            let accepted = u32::try_from(entries.len()).map_err(|_| NtStatus::INVALID_PARAMETER)?;
            let next_context = if status.is_success() {
                start
                    .checked_add(accepted)
                    .ok_or(NtStatus::INVALID_PARAMETER)?
            } else {
                context
            };
            if status == NO_MORE_ENTRIES && total <= output.len() {
                output[..total].fill(0);
                return Ok(DirectoryQuery {
                    status,
                    context: next_context,
                    return_length,
                    written: return_length,
                });
            }
            if total > output.len() || !status.is_success() {
                return Ok(DirectoryQuery {
                    status,
                    context: next_context,
                    return_length,
                    written: 0,
                });
            }
            output[..total].fill(0);
            let mut string_offset = (entries.len() + 1) * RECORD_SIZE;
            for (index, (name, type_name)) in entries.iter().enumerate() {
                for (field, value) in [*name, type_name].into_iter().enumerate() {
                    let length = (value.len() * 2) as u16;
                    let record = index * RECORD_SIZE + field * 16;
                    output[record..record + 2].copy_from_slice(&length.to_le_bytes());
                    output[record + 2..record + 4].copy_from_slice(&(length + 2).to_le_bytes());
                    output[record + 8..record + 16]
                        .copy_from_slice(&(output_base + string_offset as u64).to_le_bytes());
                    for unit in value.as_units() {
                        output[string_offset..string_offset + 2]
                            .copy_from_slice(&unit.to_le_bytes());
                        string_offset += 2;
                    }
                    string_offset += 2;
                }
            }
            Ok(DirectoryQuery {
                status,
                context: next_context,
                return_length,
                written: total as u32,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientKind;
    use nt_types::NtPath;

    fn setup() -> (ObjectManager, ClientId) {
        let mut om = ObjectManager::new();
        om.bootstrap_namespace().unwrap();
        let client = om.register_client(ClientKind::ExecutiveService, AccessMode::KernelMode);
        (om, client)
    }

    fn create(om: &mut ObjectManager, client: ClientId, path: &str) -> HandleValue {
        om.create_directory_handle(
            client,
            None,
            &UnicodeString::from_str(path),
            rights::directory::ALL_ACCESS,
            ObjAttrFlags::empty(),
        )
        .unwrap()
        .handle
    }

    #[test]
    fn create_openif_and_close_share_canonical_identity() {
        let (mut om, client) = setup();
        let name = UnicodeString::from_str("\\Device\\DirectoryTest");
        let a = om
            .create_directory_handle(
                client,
                None,
                &name,
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        assert!(a.created);
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &name,
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        let b = om
            .create_directory_handle(
                client,
                None,
                &name,
                rights::directory::QUERY,
                ObjAttrFlags::OPEN_IF,
            )
            .unwrap();
        assert!(!b.created);
        let a_object = om
            .reference_by_handle(client, a.handle, om.directory_type(), AccessMask::empty())
            .unwrap();
        let b_object = om
            .reference_by_handle(client, b.handle, om.directory_type(), AccessMask::empty())
            .unwrap();
        assert_eq!(a_object.id(), b_object.id());
        let path = NtPath::parse(name.as_units()).unwrap();
        assert_eq!(
            om.lookup_path(&path, CaseSensitivity::CaseSensitive)
                .unwrap()
                .id(),
            a_object.id()
        );
        om.close_handle(client, a.handle).unwrap();
        assert!(om
            .lookup_path(&path, CaseSensitivity::CaseSensitive)
            .is_ok());
        om.close_handle(client, b.handle).unwrap();
        assert!(matches!(
            om.lookup_path(&path, CaseSensitivity::CaseSensitive),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        ));
        assert!(matches!(
            om.reference_by_handle(client, a.handle, None, AccessMask::empty()),
            Err(NtStatus::INVALID_HANDLE)
        ));
    }

    #[test]
    fn failed_access_does_not_publish_name_or_handle() {
        let (mut om, _) = setup();
        let client = om.register_client(ClientKind::NativeUser, AccessMode::UserMode);
        let name = UnicodeString::from_str("\\Device\\Denied");
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &name,
                AccessMask::from_bits_retain(0x8000),
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::ACCESS_DENIED)
        );
        assert_eq!(om.open_handle_count(client), Ok(0));
        assert!(matches!(
            om.lookup_path(
                &NtPath::parse(name.as_units()).unwrap(),
                CaseSensitivity::CaseSensitive
            ),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        ));
        om.close_client(client).unwrap();
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &name,
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    #[test]
    fn relative_root_type_stale_and_client_scope() {
        let (mut om, client) = setup();
        let root = create(&mut om, client, "\\Device\\Parent");
        let child = om
            .create_directory_handle(
                client,
                Some(root),
                &UnicodeString::from_str("Child"),
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        let opened = om
            .open_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\Device\\Parent\\Child"),
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        assert_eq!(
            om.reference_by_handle(client, child.handle, None, AccessMask::empty())
                .unwrap()
                .id(),
            om.reference_by_handle(client, opened, None, AccessMask::empty())
                .unwrap()
                .id()
        );
        let other = om.register_client(ClientKind::ExecutiveService, AccessMode::KernelMode);
        assert_eq!(
            om.open_directory_handle(
                other,
                Some(root),
                &UnicodeString::from_str("Child"),
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(
            om.open_directory_handle(
                client,
                Some(root),
                &UnicodeString::from_str("\\Device"),
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(OBJECT_PATH_SYNTAX_BAD)
        );
        om.close_handle(client, root).unwrap();
        assert_eq!(
            om.open_directory_handle(
                client,
                Some(root),
                &UnicodeString::from_str("Child"),
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    #[test]
    fn case_distinct_children_reap_exact_name_and_preserve_utf16() {
        let (mut om, client) = setup();
        let upper = create(&mut om, client, "\\Device\\Aa");
        let lower = create(&mut om, client, "\\Device\\aa");
        let unicode = create(&mut om, client, "\\Device\\\u{4e2d}\u{1f600}");
        om.close_handle(client, lower).unwrap();
        let found = om
            .open_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\device\\AA"),
                rights::directory::QUERY,
                ObjAttrFlags::CASE_INSENSITIVE,
            )
            .unwrap();
        assert_eq!(
            om.reference_by_handle(client, found, None, AccessMask::empty())
                .unwrap()
                .id(),
            om.reference_by_handle(client, upper, None, AccessMask::empty())
                .unwrap()
                .id()
        );
        let obj = om
            .reference_by_handle(client, unicode, None, AccessMask::empty())
            .unwrap();
        assert_eq!(obj.name().unwrap().as_units(), &[0x4e2d, 0xd83d, 0xde00]);
    }

    #[test]
    fn create_admits_only_leaf_names_with_encodable_enumeration_lengths() {
        let (mut om, client) = setup();
        let root = create(&mut om, client, "\\Device\\LongNames");
        let longest = UnicodeString::from_units(&alloc::vec![b'a' as u16; 32766]);
        let child = om
            .create_directory_handle(
                client,
                Some(root),
                &longest,
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        let mut output = alloc::vec![0; 65632];
        let result = om
            .query_directory(client, root, 0, true, true, 0, &mut output)
            .unwrap();
        assert_eq!(result.status, NtStatus::SUCCESS);
        assert_eq!(u16::from_le_bytes(output[0..2].try_into().unwrap()), 65532);
        assert_eq!(u16::from_le_bytes(output[2..4].try_into().unwrap()), 65534);
        om.close_handle(client, child.handle).unwrap();

        let too_long = UnicodeString::from_units(&alloc::vec![b'a' as u16; 32767]);
        let before = om.open_handle_count(client).unwrap();
        assert_eq!(
            om.create_directory_handle(
                client,
                Some(root),
                &too_long,
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::OBJECT_NAME_INVALID)
        );
        assert_eq!(om.open_handle_count(client).unwrap(), before);
        let result = om
            .query_directory(client, root, 0, true, false, 0, &mut output)
            .unwrap();
        assert_eq!(result.status, NO_MORE_ENTRIES);
    }

    #[test]
    fn type_mismatch_and_attributes_are_not_success() {
        let (mut om, client) = setup();
        let root = om.root().unwrap();
        let link = om
            .create_symbolic_link(
                &root,
                &UnicodeString::from_str("LinkTest"),
                NtPath::parse_str("\\Device").unwrap(),
                false,
            )
            .unwrap();
        let link_handle = om
            .open(
                client,
                &link,
                AccessMask::GENERIC_READ,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        assert_eq!(
            om.open_directory_handle(
                client,
                Some(link_handle),
                &UnicodeString::new(),
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        );
        om.create_driver(
            &root,
            &UnicodeString::from_str("DriverTest"),
            crate::ComponentId(5),
            1,
            false,
        )
        .unwrap();
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\DriverTest"),
                rights::directory::QUERY,
                ObjAttrFlags::OPEN_IF
            ),
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\Device\\Invalid"),
                rights::directory::QUERY,
                ObjAttrFlags::EXCLUSIVE
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            om.open_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\Device"),
                rights::directory::QUERY,
                ObjAttrFlags::OPEN_LINK
            ),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn enumeration_packs_real_names_types_and_relative_pointers() {
        let (mut om, client) = setup();
        let root = create(&mut om, client, "\\Device\\Query");
        let child = om
            .create_directory_handle(
                client,
                Some(root),
                &UnicodeString::from_units(&[0x4e2d, 0xd800]),
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        let mut output = [0xa5; 128];
        let result = om
            .query_directory(client, root, 55, true, false, 0x1000, &mut output)
            .unwrap();
        assert_eq!(result.status, NtStatus::SUCCESS);
        assert_eq!(result.context, 1);
        assert_eq!(result.written, 90);
        assert_eq!(result.return_length, 90);
        assert_eq!(&output[0..4], &[4, 0, 6, 0]);
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            0x1040
        );
        assert_eq!(
            u64::from_le_bytes(output[24..32].try_into().unwrap()),
            0x1046
        );
        assert_eq!(&output[32..64], &[0; 32]);
        assert_eq!(&output[64..70], &[0x2d, 0x4e, 0, 0xd8, 0, 0]);
        assert_eq!(
            &output[70..90],
            &[
                b'D', 0, b'i', 0, b'r', 0, b'e', 0, b'c', 0, b't', 0, b'o', 0, b'r', 0, b'y', 0, 0,
                0
            ]
        );
        assert_eq!(output[90], 0xa5);
        om.close_handle(client, child.handle).unwrap();
        let end = om
            .query_directory(client, root, result.context, false, false, 0, &mut [])
            .unwrap();
        assert_eq!(end.status, NO_MORE_ENTRIES);
        assert_eq!(end.context, 1);
    }

    #[test]
    fn enumeration_partial_single_restart_and_failure_contexts() {
        let (mut om, client) = setup();
        let root = create(&mut om, client, "\\Device\\Pages");
        for name in ["a", "b"] {
            om.create_directory_handle(
                client,
                Some(root),
                &UnicodeString::from_str(name),
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        }
        let mut output = [0xa5; 88];
        let first = om
            .query_directory(client, root, 0, false, false, 0, &mut output)
            .unwrap();
        assert_eq!(first.status, MORE_ENTRIES);
        assert_eq!(first.context, 1);
        let second = om
            .query_directory(client, root, first.context, false, true, 0, &mut output)
            .unwrap();
        assert_eq!(second.status, NtStatus::SUCCESS);
        assert_eq!(second.context, 2);
        let mut tiny = [0x77; 40];
        let small = om
            .query_directory(client, root, 1, false, true, 0, &mut tiny)
            .unwrap();
        assert_eq!(small.status, NtStatus::BUFFER_TOO_SMALL);
        assert_eq!(small.context, 1);
        assert_eq!(small.return_length, 88);
        assert_eq!(small.written, 0);
        assert_eq!(tiny, [0x77; 40]);
        let overflow = om.query_directory(client, root, 1, false, false, u64::MAX, &mut output);
        assert_eq!(overflow, Err(NtStatus::INVALID_PARAMETER));
        let restart = om
            .query_directory(client, root, 2, true, true, 0, &mut output)
            .unwrap();
        assert_eq!(restart.context, 1);
        let no_access = om
            .open_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\Device\\Pages"),
                rights::directory::TRAVERSE,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        assert_eq!(
            om.query_directory(client, no_access, 0, true, false, 0, &mut output),
            Err(NtStatus::ACCESS_DENIED)
        );
    }

    #[test]
    fn zero_buffer_and_empty_directory_have_nt5_lengths_and_cursor_rules() {
        let (mut om, client) = setup();
        let root = create(&mut om, client, "\\Device\\EmptyProbe");
        let empty = om
            .query_directory(client, root, 19, true, false, 0, &mut [])
            .unwrap();
        assert_eq!(
            empty,
            DirectoryQuery {
                status: NO_MORE_ENTRIES,
                context: 19,
                return_length: 32,
                written: 0
            }
        );
        let mut output = [0xa5; 32];
        let empty = om
            .query_directory(client, root, 19, true, false, 0, &mut output)
            .unwrap();
        assert_eq!(empty.written, 32);
        assert_eq!(output, [0; 32]);
        om.create_directory_handle(
            client,
            Some(root),
            &UnicodeString::from_str("a"),
            rights::directory::QUERY,
            ObjAttrFlags::empty(),
        )
        .unwrap();
        let probe = om
            .query_directory(client, root, 19, true, false, 0, &mut [])
            .unwrap();
        assert_eq!(
            probe,
            DirectoryQuery {
                status: MORE_ENTRIES,
                context: 0,
                return_length: 32,
                written: 0
            }
        );
        let single = om
            .query_directory(client, root, 19, true, true, 0, &mut [])
            .unwrap();
        assert_eq!(
            single,
            DirectoryQuery {
                status: NtStatus::BUFFER_TOO_SMALL,
                context: 19,
                return_length: 88,
                written: 0
            }
        );
    }

    #[test]
    fn create_follows_final_and_intermediate_links_with_one_reparse_budget() {
        let (mut om, client) = setup();
        let root = om.root().unwrap();
        let target = create(&mut om, client, "\\Device\\LinkTarget");
        om.create_symbolic_link(
            &root,
            &UnicodeString::from_str("ExistingLink"),
            NtPath::parse_str("\\Device\\LinkTarget").unwrap(),
            true,
        )
        .unwrap();
        let opened = om
            .create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\ExistingLink"),
                rights::directory::QUERY,
                ObjAttrFlags::OPEN_IF,
            )
            .unwrap();
        assert!(!opened.created);
        assert_eq!(
            om.reference_by_handle(client, opened.handle, None, AccessMask::empty())
                .unwrap()
                .id(),
            om.reference_by_handle(client, target, None, AccessMask::empty())
                .unwrap()
                .id()
        );
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\ExistingLink"),
                rights::directory::QUERY,
                ObjAttrFlags::empty()
            ),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        let child = om
            .create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\ExistingLink\\Child"),
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        let found = om
            .lookup_path(
                &NtPath::parse_str("\\Device\\LinkTarget\\Child").unwrap(),
                CaseSensitivity::CaseSensitive,
            )
            .unwrap();
        assert_eq!(
            found.id(),
            om.reference_by_handle(client, child.handle, None, AccessMask::empty())
                .unwrap()
                .id()
        );
        om.create_symbolic_link(
            &root,
            &UnicodeString::from_str("DanglingLink"),
            NtPath::parse_str("\\Device\\NotYetCreated").unwrap(),
            true,
        )
        .unwrap();
        let created = om
            .create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\DanglingLink"),
                rights::directory::QUERY,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        assert!(created.created);
        assert!(om
            .lookup_path(
                &NtPath::parse_str("\\Device\\NotYetCreated").unwrap(),
                CaseSensitivity::CaseSensitive
            )
            .is_ok());
        om.create_symbolic_link(
            &root,
            &UnicodeString::from_str("CycleLink"),
            NtPath::parse_str("\\CycleLink").unwrap(),
            true,
        )
        .unwrap();
        let before = om.open_handle_count(client).unwrap();
        assert_eq!(
            om.create_directory_handle(
                client,
                None,
                &UnicodeString::from_str("\\CycleLink"),
                rights::directory::QUERY,
                ObjAttrFlags::OPEN_IF
            ),
            Err(NtStatus::OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(om.open_handle_count(client).unwrap(), before);
    }
}
