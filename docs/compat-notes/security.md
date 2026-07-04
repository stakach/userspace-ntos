# NT Security Reference Monitor (tokens + access check) — compatibility notes

The NT Security Reference Monitor (spec: NT Security Reference Monitor + Tokens + Object Access).
SIDs, tokens, security descriptors, and the access-check algorithm.

## nt-security (implemented, Milestones 27.1-27.3)

- SIDs (§7.1): `Sid` + well-known SIDs (Everyone/LocalSystem/Administrators/Users/Authenticated
  Users/Creator Owner + local synthetic accounts), SDDL string form (`S-1-5-32-544`).
- Tokens (§7.2-§7.4, §17): `AccessToken` (user/groups/privileges/owner) + default `system()`
  (all privileges), `admin()` (load-driver/take-ownership/debug), `user()` (change-notify only);
  `TokenGroup` (enabled/deny-only), `TokenPrivilege` (has_privilege), the required SE_* names.
- Descriptors (§7.5-§7.7): `SecurityDescriptor` (owner/group/dacl/sacl), `Acl`, `Ace`
  (AccessAllowed/AccessDenied/SystemAudit).
- Access masks (§8): standard rights (DELETE/READ_CONTROL/WRITE_DAC/WRITE_OWNER/SYNCHRONIZE),
  ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED, generic rights + `GenericMapping.map`.
- Access check (§9): `access_check` — generic mapping, MAXIMUM_ALLOWED union, deny-before-allow in
  ACL order, accumulate from user + enabled groups (deny ACEs also match deny-only groups),
  null DACL grants all / empty grants none, owner READ_CONTROL (§9.6), privilege overrides
  (ACCESS_SYSTEM_SECURITY→SeSecurityPrivilege, WRITE_OWNER→SeTakeOwnershipPrivilege §9.7),
  KernelMode DACL bypass (§9.3). `privilege_check` helper.
- 8 unit tests: SID/SDDL, default tokens + privilege checks, allow ACE, deny-before-allow,
  null/empty DACL, owner rights + generic mapping, MAXIMUM_ALLOWED union, privilege overrides +
  kernel bypass.

## Access checks in QEMU (implemented, Milestone 27 — `configuration-manager`)

The `configuration-manager` component now also proves the access-check algorithm bare-metal on
seL4 (34/34 checks): well-known SID/SDDL formatting; a canonical DACL (deny Users write, allow
Everyone read+write) where a standard user gets read but is denied write (deny-before-allow);
owner READ_CONTROL against an empty DACL + KernelMode DACL bypass; and privilege overrides —
ACCESS_SYSTEM_SECURITY granted to System (SeSecurityPrivilege) but denied to a user, and
WRITE_OWNER granted to an admin via SeTakeOwnershipPrivilege.
