//! `RtlNewSecurityGrantedAccess`: which part of a requested access a new object's creator is
//! granted by privilege rather than by the object's security descriptor.
//!
//! ReactOS `sdk/lib/rtl/security.c` grants `ACCESS_SYSTEM_SECURITY` unconditionally (a FIXME
//! there). NT grants it only when the caller's token holds `SeSecurityPrivilege`, which is what
//! this does: the token is asked through `NtPrivilegeCheck`, and only a granted privilege is
//! reported in the returned `PRIVILEGE_SET`.

pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const SE_SECURITY_PRIVILEGE: u32 = 8;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
/// `sizeof(PRIVILEGE_SET)` with its one inline `LUID_AND_ATTRIBUTES`.
pub const PRIVILEGE_SET_SIZE: u32 = 20;
const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NO_TOKEN: u32 = 0xc000_007c;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;

/// The token services the decision needs.
pub trait TokenAccess {
    /// The calling thread's impersonation token, opened for query (`NtOpenThreadToken` with
    /// `OpenAsSelf`); `Err(STATUS_NO_TOKEN)` when the thread is not impersonating.
    fn open_thread_token(&mut self) -> Result<u64, u32>;
    /// The process's primary token, opened for query.
    fn open_process_token(&mut self) -> Result<u64, u32>;
    /// `NtPrivilegeCheck` for one privilege; `Ok(true)` when the token holds it enabled.
    fn holds_privilege(&mut self, token: u64, privilege: u32) -> Result<bool, u32>;
    fn close(&mut self, handle: u64);
}

/// The `PRIVILEGE_SET` a granted `ACCESS_SYSTEM_SECURITY` is reported in.
pub fn privilege_set(granted: bool) -> [u8; PRIVILEGE_SET_SIZE as usize] {
    let mut set = [0u8; PRIVILEGE_SET_SIZE as usize];
    if granted {
        set[0..4].copy_from_slice(&1u32.to_le_bytes());
        set[8..12].copy_from_slice(&SE_SECURITY_PRIVILEGE.to_le_bytes());
        set[16..20].copy_from_slice(&SE_PRIVILEGE_USED_FOR_ACCESS.to_le_bytes());
    }
    set
}

/// The `PRIVILEGE_SET` asked of `NtPrivilegeCheck` for `SeSecurityPrivilege`.
pub fn security_privilege_request() -> [u8; PRIVILEGE_SET_SIZE as usize] {
    let mut set = [0u8; PRIVILEGE_SET_SIZE as usize];
    set[0..4].copy_from_slice(&1u32.to_le_bytes());
    set[4..8].copy_from_slice(&PRIVILEGE_SET_ALL_NECESSARY.to_le_bytes());
    set[8..12].copy_from_slice(&SE_SECURITY_PRIVILEGE.to_le_bytes());
    set
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantedAccess {
    /// Access still to be granted by the security descriptor.
    pub remaining: u32,
    /// Whether `ACCESS_SYSTEM_SECURITY` was granted by `SeSecurityPrivilege`.
    pub security_privilege_used: bool,
}

/// `mapped_access` is the desired access after generic mapping. `token` is the caller's
/// handle, or `None` to use the caller's effective token (impersonation, else primary).
pub fn new_security_granted_access(
    ops: &mut impl TokenAccess,
    mapped_access: u32,
    token: Option<u64>,
) -> Result<GrantedAccess, u32> {
    if mapped_access & ACCESS_SYSTEM_SECURITY == 0 {
        return Ok(GrantedAccess { remaining: mapped_access, security_privilege_used: false });
    }
    let (token, opened) = match token {
        Some(token) => (token, false),
        None => match ops.open_thread_token() {
            Ok(token) => (token, true),
            Err(STATUS_NO_TOKEN) => (ops.open_process_token()?, true),
            Err(status) => return Err(status),
        },
    };
    let held = ops.holds_privilege(token, SE_SECURITY_PRIVILEGE);
    if opened {
        ops.close(token);
    }
    let held = held?;
    Ok(GrantedAccess {
        remaining: if held { mapped_access & !ACCESS_SYSTEM_SECURITY } else { mapped_access },
        security_privilege_used: held,
    })
}

/// Whether the caller's `PRIVILEGE_SET` buffer can take the answer; `length` receives the size
/// needed either way.
pub fn privilege_buffer_status(length: &mut u32) -> u32 {
    let fits = *length >= PRIVILEGE_SET_SIZE;
    *length = PRIVILEGE_SET_SIZE;
    if fits { STATUS_SUCCESS } else { STATUS_BUFFER_TOO_SMALL }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[derive(Default)]
    struct Tokens {
        impersonating: bool,
        privileged: Vec<u64>,
        opened: Vec<u64>,
        closed: Vec<u64>,
        checked: Vec<u64>,
    }

    impl TokenAccess for Tokens {
        fn open_thread_token(&mut self) -> Result<u64, u32> {
            if self.impersonating {
                self.opened.push(0x20);
                Ok(0x20)
            } else {
                Err(STATUS_NO_TOKEN)
            }
        }
        fn open_process_token(&mut self) -> Result<u64, u32> {
            self.opened.push(0x10);
            Ok(0x10)
        }
        fn holds_privilege(&mut self, token: u64, privilege: u32) -> Result<bool, u32> {
            assert_eq!(privilege, SE_SECURITY_PRIVILEGE);
            self.checked.push(token);
            Ok(self.privileged.contains(&token))
        }
        fn close(&mut self, handle: u64) {
            self.closed.push(handle);
        }
    }

    const READ_CONTROL: u32 = 0x0002_0000;

    #[test]
    fn system_security_is_granted_only_with_the_privilege() {
        let mut tokens = Tokens { privileged: vec![0x10], ..Tokens::default() };
        let granted = new_security_granted_access(
            &mut tokens,
            ACCESS_SYSTEM_SECURITY | READ_CONTROL,
            None,
        )
        .unwrap();
        assert_eq!(granted, GrantedAccess { remaining: READ_CONTROL, security_privilege_used: true });
        assert_eq!((tokens.checked, tokens.closed), (vec![0x10], vec![0x10]));

        let mut unprivileged = Tokens::default();
        let refused = new_security_granted_access(
            &mut unprivileged,
            ACCESS_SYSTEM_SECURITY | READ_CONTROL,
            None,
        )
        .unwrap();
        assert_eq!(
            refused,
            GrantedAccess {
                remaining: ACCESS_SYSTEM_SECURITY | READ_CONTROL,
                security_privilege_used: false
            }
        );
        assert_eq!(privilege_set(false), [0u8; 20]);
    }

    #[test]
    fn the_impersonation_token_and_a_caller_token_take_precedence() {
        let mut tokens =
            Tokens { impersonating: true, privileged: vec![0x20], ..Tokens::default() };
        assert!(new_security_granted_access(&mut tokens, ACCESS_SYSTEM_SECURITY, None)
            .unwrap()
            .security_privilege_used);
        assert_eq!(tokens.opened, vec![0x20]);

        let mut tokens = Tokens { privileged: vec![0x44], ..Tokens::default() };
        assert!(new_security_granted_access(&mut tokens, ACCESS_SYSTEM_SECURITY, Some(0x44))
            .unwrap()
            .security_privilege_used);
        assert!(tokens.opened.is_empty() && tokens.closed.is_empty());
    }

    #[test]
    fn no_token_is_needed_without_a_system_security_request() {
        let mut tokens = Tokens::default();
        let granted = new_security_granted_access(&mut tokens, READ_CONTROL, None).unwrap();
        assert_eq!(granted.remaining, READ_CONTROL);
        assert!(tokens.opened.is_empty() && tokens.checked.is_empty());
    }

    #[test]
    fn the_answer_needs_one_privilege_set() {
        let mut length = 4;
        assert_eq!(privilege_buffer_status(&mut length), STATUS_BUFFER_TOO_SMALL);
        assert_eq!(length, 20);
        let mut length = 64;
        assert_eq!(privilege_buffer_status(&mut length), STATUS_SUCCESS);
        assert_eq!(length, 20);
        let set = privilege_set(true);
        assert_eq!(u32::from_le_bytes(set[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(set[8..12].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(set[16..20].try_into().unwrap()), 0x8000_0000);
        assert_eq!(u32::from_le_bytes(security_privilege_request()[4..8].try_into().unwrap()), 1);
    }
}
