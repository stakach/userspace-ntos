//! `SetPrivateObjectSecurityEx` / `RtlSetSecurityObjectEx` with auto-inheritance.
//!
//! With `SEF_DACL_AUTO_INHERIT` (or `SEF_SACL_AUTO_INHERIT`) a caller that replaces an ACL
//! replaces only its explicit ACEs. The object keeps the ACEs it inherited from its parent
//! (`INHERITED_ACE`), after the new explicit ones, unless the result is protected from
//! inheritance. ACEs marked inherited in the modification are not the caller's to set and are
//! dropped. The object stays auto-inherited if it was, or becomes so when the modification
//! requests it (`SE_*_AUTO_INHERIT_REQ`).

use alloc::vec::Vec;

use super::{
    build_self_relative_descriptor, native_acl_aces, parse_self_relative_descriptor,
    set_security_descriptor_bytes, DescriptorBuild, ACL_HEADER_SIZE, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PROTECTED_SACL_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_PROTECTED,
};
use crate::native_acl::{NativeAcl, STATUS_INVALID_ACL};
use crate::{SEF_DACL_AUTO_INHERIT, SEF_SACL_AUTO_INHERIT};

/// `INHERITED_ACE` in an ACE header's flags.
const INHERITED_ACE: u8 = 0x10;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

struct AclRule {
    flag: u32,
    information: u32,
    protected_information: u32,
    auto_inherit_req: u16,
    auto_inherited: u16,
    protected: u16,
}

const DACL: AclRule = AclRule {
    flag: SEF_DACL_AUTO_INHERIT,
    information: DACL_SECURITY_INFORMATION,
    protected_information: PROTECTED_DACL_SECURITY_INFORMATION,
    auto_inherit_req: SE_DACL_AUTO_INHERIT_REQ,
    auto_inherited: SE_DACL_AUTO_INHERITED,
    protected: SE_DACL_PROTECTED,
};

const SACL: AclRule = AclRule {
    flag: SEF_SACL_AUTO_INHERIT,
    information: SACL_SECURITY_INFORMATION,
    protected_information: PROTECTED_SACL_SECURITY_INFORMATION,
    auto_inherit_req: SE_SACL_AUTO_INHERIT_REQ,
    auto_inherited: SE_SACL_AUTO_INHERITED,
    protected: SE_SACL_PROTECTED,
};

/// The modification's explicit ACEs followed, unless protected, by the object's inherited ACEs.
fn merged_acl(
    modification: &[u8],
    current: Option<&[u8]>,
    keep_inherited: bool,
) -> Result<Vec<u8>, u32> {
    let modification = NativeAcl::validated_prefix(modification).map_err(|error| error.status())?;
    let current = current
        .map(NativeAcl::validated_prefix)
        .transpose()
        .map_err(|error| error.status())?
        .filter(|_| keep_inherited);
    let explicit = native_acl_aces(modification).filter(|ace| ace[1] & INHERITED_ACE == 0);
    let inherited = current
        .into_iter()
        .flat_map(native_acl_aces)
        .filter(|ace| ace[1] & INHERITED_ACE != 0);
    let aces: Vec<&[u8]> = explicit.chain(inherited).collect();
    let size = aces
        .iter()
        .try_fold(ACL_HEADER_SIZE, |size, ace| size.checked_add(ace.len()))
        .ok_or(STATUS_INVALID_ACL)?;
    let size_u16 = u16::try_from(size).map_err(|_| STATUS_INVALID_ACL)?;
    let count = u16::try_from(aces.len()).map_err(|_| STATUS_INVALID_ACL)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    out.resize(ACL_HEADER_SIZE, 0);
    out[0] = core::cmp::max(modification[0], current.map_or(0, |acl| acl[0]));
    out[2..4].copy_from_slice(&size_u16.to_le_bytes());
    out[4..6].copy_from_slice(&count.to_le_bytes());
    for ace in aces {
        out.extend_from_slice(ace);
    }
    Ok(out)
}

/// [`set_security_descriptor_bytes`] honouring `SEF_DACL_AUTO_INHERIT` / `SEF_SACL_AUTO_INHERIT`.
pub fn set_security_descriptor_bytes_ex(
    object_descriptor: &[u8],
    security_information: u32,
    modification_descriptor: &[u8],
    auto_inherit_flags: u32,
) -> Result<Vec<u8>, u32> {
    let updated =
        set_security_descriptor_bytes(object_descriptor, security_information, modification_descriptor)?;
    let applies = |rule: &AclRule| {
        auto_inherit_flags & rule.flag != 0 && security_information & rule.information != 0
    };
    if !applies(&DACL) && !applies(&SACL) {
        return Ok(updated);
    }
    let current = parse_self_relative_descriptor(object_descriptor)?;
    let modification = parse_self_relative_descriptor(modification_descriptor)?;
    let result = parse_self_relative_descriptor(&updated)?;
    let mut control = result.control;
    let mut acls: [Option<Vec<u8>>; 2] = [None, None];
    for (slot, rule, modification_acl, current_acl) in [
        (0, &DACL, modification.dacl, current.dacl),
        (1, &SACL, modification.sacl, current.sacl),
    ] {
        if !applies(rule) {
            continue;
        }
        let protected = control & rule.protected != 0
            || security_information & rule.protected_information != 0;
        if let Some(modification_acl) = modification_acl {
            acls[slot] = Some(merged_acl(modification_acl, current_acl, !protected)?);
        }
        let auto_inherited = current.control & rule.auto_inherited != 0
            || modification.control & rule.auto_inherit_req != 0;
        control &= !(rule.auto_inherit_req | rule.auto_inherited);
        if auto_inherited {
            control |= rule.auto_inherited;
        }
    }
    build_self_relative_descriptor(DescriptorBuild {
        owner: result.owner,
        group: result.group,
        sacl_present: result.sacl_present,
        sacl: acls[1].as_deref().or(result.sacl),
        dacl_present: result.dacl_present,
        dacl: acls[0].as_deref().or(result.dacl),
        control,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    fn allow(sid: &[u8; 12], mask: u32, flags: u8) -> Vec<u8> {
        let size = 8 + sid.len() as u16;
        let mut ace = vec![0u8, flags];
        ace.extend_from_slice(&size.to_le_bytes());
        ace.extend_from_slice(&mask.to_le_bytes());
        ace.extend_from_slice(sid);
        ace
    }

    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
        let mut out = vec![2u8, 0];
        out.extend_from_slice(&(size as u16).to_le_bytes());
        out.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        for ace in aces {
            out.extend_from_slice(ace);
        }
        out
    }

    fn descriptor(control: u16, dacl: &[u8]) -> Vec<u8> {
        build_self_relative_descriptor(DescriptorBuild {
            owner: Some(&SYSTEM),
            group: Some(&SYSTEM),
            sacl_present: false,
            sacl: None,
            dacl_present: true,
            dacl: Some(dacl),
            control,
        })
        .unwrap()
    }

    fn dacl_aces(descriptor: &[u8]) -> Vec<(u32, u8)> {
        let parsed = parse_self_relative_descriptor(descriptor).unwrap();
        native_acl_aces(parsed.dacl.unwrap())
            .map(|ace| (u32::from_le_bytes(ace[4..8].try_into().unwrap()), ace[1]))
            .collect()
    }

    fn control(descriptor: &[u8]) -> u16 {
        parse_self_relative_descriptor(descriptor).unwrap().control
    }

    #[test]
    fn auto_inherit_keeps_the_objects_inherited_aces_after_the_new_explicit_ones() {
        let object = descriptor(
            SE_DACL_AUTO_INHERITED,
            &acl(&[allow(&WORLD, 0x1, 0), allow(&SYSTEM, 0x10, INHERITED_ACE)]),
        );
        // The caller sets one explicit ACE and passes an inherited one it may not set.
        let modification = descriptor(
            0,
            &acl(&[allow(&WORLD, 0x2, 0), allow(&WORLD, 0x40, INHERITED_ACE)]),
        );
        let updated = set_security_descriptor_bytes_ex(
            &object,
            DACL_SECURITY_INFORMATION,
            &modification,
            SEF_DACL_AUTO_INHERIT,
        )
        .unwrap();
        assert_eq!(dacl_aces(&updated), vec![(0x2, 0), (0x10, INHERITED_ACE)]);
        assert_ne!(control(&updated) & SE_DACL_AUTO_INHERITED, 0);

        // Without the flag the modification's DACL replaces the object's whole DACL.
        let plain =
            set_security_descriptor_bytes(&object, DACL_SECURITY_INFORMATION, &modification)
                .unwrap();
        assert_eq!(dacl_aces(&plain), vec![(0x2, 0), (0x40, INHERITED_ACE)]);
    }

    #[test]
    fn a_protected_result_drops_inherited_aces() {
        let object = descriptor(
            SE_DACL_AUTO_INHERITED,
            &acl(&[allow(&SYSTEM, 0x10, INHERITED_ACE)]),
        );
        let modification = descriptor(SE_DACL_PROTECTED, &acl(&[allow(&WORLD, 0x2, 0)]));
        let updated = set_security_descriptor_bytes_ex(
            &object,
            DACL_SECURITY_INFORMATION,
            &modification,
            SEF_DACL_AUTO_INHERIT,
        )
        .unwrap();
        assert_eq!(dacl_aces(&updated), vec![(0x2, 0)]);
        assert_ne!(control(&updated) & SE_DACL_PROTECTED, 0);

        let unprotected_modification = descriptor(0, &acl(&[allow(&WORLD, 0x2, 0)]));
        let by_information = set_security_descriptor_bytes_ex(
            &object,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            &unprotected_modification,
            SEF_DACL_AUTO_INHERIT,
        )
        .unwrap();
        assert_eq!(dacl_aces(&by_information), vec![(0x2, 0)]);
    }

    #[test]
    fn an_auto_inherit_request_marks_the_object_auto_inherited() {
        let object = descriptor(0, &acl(&[allow(&SYSTEM, 0x10, INHERITED_ACE)]));
        let modification = descriptor(SE_DACL_AUTO_INHERIT_REQ, &acl(&[allow(&WORLD, 0x2, 0)]));
        let updated = set_security_descriptor_bytes_ex(
            &object,
            DACL_SECURITY_INFORMATION,
            &modification,
            SEF_DACL_AUTO_INHERIT,
        )
        .unwrap();
        let control = control(&updated);
        assert_ne!(control & SE_DACL_AUTO_INHERITED, 0);
        assert_eq!(control & SE_DACL_AUTO_INHERIT_REQ, 0);
        // A DACL the caller did not select is left as it was.
        let untouched = set_security_descriptor_bytes_ex(
            &object,
            0x1, // OWNER_SECURITY_INFORMATION
            &modification,
            SEF_DACL_AUTO_INHERIT,
        )
        .unwrap();
        assert_eq!(dacl_aces(&untouched), vec![(0x10, INHERITED_ACE)]);
    }
}
