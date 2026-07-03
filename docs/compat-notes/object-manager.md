# Object Manager — behavioural compatibility notes

Running notes on where the userspace-ntos Object Manager matches, approximates,
or intentionally diverges from Windows NT behaviour. Compatibility target is
**behavioural, not internal binary identity** (spec §5). Reference material:
ReactOS `ntoskrnl/ob/` (open implementation), Microsoft Learn docs (concepts).
No proprietary NT source is copied; only documented semantics are reproduced.

## Status codes (`nt-status`)

- `NtStatus(i32)`; the constants are the **real Windows NTSTATUS values**
  (`STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034`, etc.) so a status that reaches a
  native client is bit-for-bit what NT returns.
- `is_success` = `NT_SUCCESS` = `status >= 0` (severity success/informational).

## Ids and handles (`nt-types`)

- `ObjectId` and `HandleValue` are **generation-protected**: 24-bit generation
  (high) + 40-bit slot (low). A reused slot bumps its generation, so a stale id
  or handle never resolves to a new object (`STATUS_INVALID_HANDLE`). Generation
  wraps within 24 bits and skips 0 (0 stays reserved as null). The split may
  change before v1 but staleness must remain detectable.
- Handles are **not** object ids and are not valid across clients (distinct
  newtypes, per-client tables — enforced in later milestones).

## Strings and paths (`nt-types`)

- `UnicodeString` is UTF-16 (`Vec<u16>`), NT's native encoding.
- Case-insensitive comparison (`OBJ_CASE_INSENSITIVE`) uses **ASCII case folding
  only** for MVP; full Unicode case folding is deferred (spec §9.5). Directories
  will store the original name plus a folded lookup key.
- `NtPath::parse` accepts **absolute** NT paths only (v0.1): separator `\`, must
  start with `\`, empty components (`\\` or trailing `\`) rejected, bare `\`
  parses to the root (zero components). Relative paths and Win32 path translation
  are out of scope at this layer (`\??` is just a normal namespace here).

## Access masks (`nt-types`)

- `AccessMask` bits are the real Windows values (`GENERIC_READ = 0x80000000`,
  `DELETE = 0x00010000`, …). Object-specific rights occupy the low 16 bits and
  are interpreted per type, so arbitrary bits are preserved (`from_bits_retain`);
  they are not named in the shared `AccessMask` flags because they collide across
  types (`DIRECTORY_QUERY == EVENT_QUERY_STATE == 0x0001`).
- `GenericMapping::map` mirrors `RtlMapGenericMask`: replace `GENERIC_*` bits with
  the type's specific rights.

## Wire ABI (`nt-object-abi`)

- Opcodes occupy the reserved SURT range `0x2000..=0x20ff` (spec §12).
- All wire structs are `#[repr(C)]`, fixed-width, no pointers/references, with
  explicit length fields; sizes/alignments are asserted at compile time.

## Lifetime model (planned, Milestone 2+)

- `pointer_count` is realised as an `Rc` strong count (single-threaded core, spec
  §15): the store holds `Weak`; strong refs are held by open handles, live
  `ObjectRef`s, named-directory entries, and the permanent flag. Last strong drop
  → the delete callback runs exactly once. This deviates from the spec's
  `AtomicUsize` sketch (§8.2) to get memory safety from Rust ownership rather than
  manual counting + unsafe. `handle_count` stays a separate counter for
  temporary-name removal. Stale-id detection is independent (generation slot-map).
