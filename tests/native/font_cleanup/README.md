# Native Private Font Cleanup

This isolated acceptance profile tests real Win32 private-font ownership at process exit.
It requires an actual ReactOS desktop and our ntdll; it is not a replacement shell or a kernel hook.

`font_run_setup.exe` is a native BootExecute setup command. It uses public NT registry calls to
install and read back `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\NtosFontAcceptance`
as `REG_EXPAND_SZ` with `%SystemRoot%\System32\font_acceptance.exe`. ReactOS Explorer processes
that ordinary Run value after its normal shell initialization. Its existing Shell and Userinit
configuration remains unchanged. The installed LiveCD BootExecute list is empty (MiniNT disables
AutoChk); this test profile adds the one setup command. The production profile adds nothing.

`font_acceptance.exe` obtains the Windows directory through Kernel32, adds
`Fonts\FreeSans.ttf` with Gdi32 `AddFontResourceExW(..., FR_PRIVATE, NULL)`, requires a positive
font count, deliberately does not call RemoveFontResourceEx, and terminates through the actual
`NtTerminateProcess`. Cleanup must therefore run through the real process-delete/font-owner path.

Both executables emit public ProcessBasicInformation PIDs, exact API results, and exit requests
using NtDisplayString. These markers alone do not prove completion: validation must correlate
each PID with the canonical terminal-committed and process-delete retirement receipts, and the
font process with actual Section view/unmap/final-reference receipts. A full desktop verdict and
screenshot are separate requirements. Retained pending ownership, stale replay denial, and stopped
physical provider cleanup are not claimed solely from this fixture's successful exit.

The strict parser requires at least one file-backed view mapped by that exact hosted process
incarnation during the font-load interval. Its map, acknowledged unmap, and successful terminal
cleanup result must agree on native allocation, provider, view, Section, mounted File, and original
initiator identities. The cleanup actor must also match the terminal process incarnation. This
does not prove a font pathname or retirement of every font view. Older logs without these copied
provenance fields are not sufficient for this strengthened receipt contract.

## Build

The sole build/test owner may run `bash tests/native/font_cleanup/build.sh` after our ntdll and
the actual ReactOS Kernel32/Gdi32 are staged. It needs Clang, nightly Rust's rust-lld, and Cargo.
The dedicated `nt-font-test-verify` tool requires exact declared imports, resolves them against
the actual DLL images (including checked forwarders), maps at nonpreferred bases, and verifies
IAT readback. The existing native-only fixture verifier is unchanged.

The generated `import-only-*.dll` files contain build-only trap anchors for import-library
generation. They must never be staged or used as runtime dependencies. Only `font_run_setup.exe`
and `font_acceptance.exe` belong in the explicit `font-cleanup` profile's System32 directory.
No fixture files, startup commands, or Run configuration belong in the production image.

The `font-cleanup` image profile stages only these two verified executables. Build the fixtures
first, then run `NTOS_IMAGE_PROFILE=font-cleanup ./run.sh --build-only`. Successful static
verification does not establish native execution or cleanup; correlate the fresh boot log with
`verify_log.py` before claiming acceptance.
