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

## Lifetime model (implemented, Milestone 2 — `nt-object-manager`)

- `pointer_count` is realised as an `Rc` strong count (single-threaded core, spec
  §15): the store holds `Weak`; strong refs are held by live `ObjectRef`s (and,
  from later milestones, open handles, named-directory entries, and the permanent
  flag). Last strong drop → `ObjectInner::Drop` runs the type's delete callback
  exactly once. This deviates from the spec's `AtomicUsize` sketch (§8.2) to get
  memory safety from Rust ownership rather than manual counting + unsafe — the
  crate has **no `unsafe`**. `handle_count` is a separate `Cell` (for the
  temporary-name removal that lands with the namespace).
- Stale-id detection is independent of lifetime: the store is a slot map of
  `{generation, Weak}`; a reused slot bumps its generation, so an `ObjectId` with
  the old generation, or one whose `Weak` is dead, resolves to
  `STATUS_INVALID_HANDLE`. Generations start at 1 so no live id is ever 0 (null).
- `create_object` returns the initial reference (`pointer_count == 1`); dropping
  the last `ObjectRef` dereferences and deletes. Named creation, handles, and
  access checks are layered on in Milestones 3–6.

## Handles (implemented, Milestone 3 — `handles.rs`)

- Handles are **per-client**: each client has its own `HandleTable` (a
  generation-protected slot map, same scheme as the object store). A
  `HandleValue` from one client never resolves in another's table.
- An open handle holds a **strong `ObjectRef`**, so it counts toward the object's
  `pointer_count` (keeping it alive) and increments `handle_count`. `close_handle`
  decrements `handle_count` and drops the reference (which may delete the object).
  Closed/reused/foreign handles resolve to `STATUS_INVALID_HANDLE`.
- `reference_by_handle` enforces the expected type
  (`STATUS_OBJECT_TYPE_MISMATCH`) and that the requested access is within the
  handle's **granted access** (`STATUS_ACCESS_DENIED`). The granted access is
  supplied at `open_handle` for now; the access *check* that computes it from
  desired-vs-valid (+ generic mapping) lands in Milestone 6.
- **Client death** (`close_client`) closes all of the client's handles
  (decrementing counts, dropping references) and retires the `ClientId` (not
  reused in v0.1, so ids never alias). Objects referenced elsewhere survive.

## Namespace (implemented, Milestone 4 — `namespace.rs`, `DirectoryBody`)

- Directories are ordinary objects; `DirectoryBody` maps names to **strong** child
  references, so the whole named tree is kept alive by the Object Manager's strong
  reference to the root. No parent→child *and* child→parent strong cycle: the child
  stores only its parent's `ObjectId` (not an `Rc`).
- `bootstrap_namespace` creates `\` (permanent) plus the MVP directories `\Device`,
  `\Driver`, `\??`, `\BaseNamedObjects`. `\??` is just a normal directory at this
  layer (no Win32 translation).
- Lookup follows spec §21: a missing/non-directory **intermediate** component →
  `STATUS_OBJECT_PATH_NOT_FOUND`; a missing **final** name →
  `STATUS_OBJECT_NAME_NOT_FOUND`. Insertion collisions → `STATUS_OBJECT_NAME_COLLISION`.
- **Case**: insertion is case-insensitive (ASCII fold, one entry per folded key);
  lookup/remove take a `CaseSensitivity`. Case-insensitive matches the folded key;
  case-sensitive matches the original name exactly. Full Unicode folding deferred.
- **Temporary vs permanent**: a directory entry holds a strong reference. A
  **temporary** named object loses its name (and that reference) when its last
  handle closes (`on_handle_closed` reaps it — wired into `close_handle` /
  `close_client`), which can then delete the object. A **permanent** object keeps
  its name until `make_temporary` clears the flag (removing the name immediately if
  no handles remain).

## Symbolic links (implemented, Milestone 5 — `namespace.rs`, `SymbolicLinkBody`)

- A `SymbolicLink` object stores an absolute `NtPath` target. `create_symbolic_link`
  inserts it into the namespace like any named object; `query_symbolic_link` returns
  the target (non-link → `STATUS_OBJECT_TYPE_MISMATCH`).
- Resolution (`lookup_path_ex`) follows links: **intermediate** links are always
  followed; the **final** component is followed unless the caller opted for
  `lookup_link` (the `OBJ_OPENLINK` behaviour, used to open/query the link itself).
  A link is followed by restarting resolution from the root with the target
  prepended to the remaining components, so `\??\Foo → \Device\Bar` makes
  `\??\Foo` resolve to the `\Device\Bar` object and `\??\Foo\x` resolve to
  `\Device\Bar\x`.
- **Loop bound**: at most 32 link expansions per lookup (spec §9.3). Exceeding it
  (a self-loop `\??\Self → \??\Self`, a mutual loop `A↔B`, …) returns
  `STATUS_OBJECT_PATH_NOT_FOUND`. (Windows' exact internal status for an exhausted
  reparse budget isn't documented; behavioural compat here is that loops are
  rejected rather than hang.)
- A **broken** target resolves as far as it can and fails naturally at the missing
  component (`STATUS_OBJECT_NAME_NOT_FOUND` / `STATUS_OBJECT_PATH_NOT_FOUND`).

## Access checks (implemented, Milestone 6 — `access.rs`)

- v0.1 has **no security descriptors**; the policy (`compute_granted`) is: map the
  requested access's `GENERIC_*` bits through the type's `GenericMapping`, resolve
  `MAXIMUM_ALLOWED` to the type's full valid access, then grant `mapped ∩ valid`.
- **Denial**: a **user-mode** caller (native/test clients) that, after mapping,
  still requests specific rights the type does not define is denied at open with
  `STATUS_ACCESS_DENIED`. A **kernel-mode** caller (Driver Host, executive) is
  trusted — the surplus bits are simply masked off, not denied. (Real NT skips the
  check entirely for `KernelMode` previous mode; masking is the conservative
  equivalent here.)
- `open` runs the check (using the client's registered access mode) and records the
  **granted** access on the handle; `reference_by_handle` then checks each request
  against that granted mask (`STATUS_ACCESS_DENIED`). `open_handle` remains the raw
  primitive that stores a caller-supplied granted mask without a check.
- Object-specific rights + generic mappings for the built-in `Directory` and
  `SymbolicLink` types use the real Windows values (`nt_types::rights`). Types that
  aren't synchronizable (e.g. Directory) don't include `SYNCHRONIZE` in their valid
  access, so requesting it is denied for user-mode callers.
