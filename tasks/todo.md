# Task: delete npfs_host.rs by converging onto the shared nt-compat-exports surface + a generic FSD entry

Baseline: main @ 3937e64, gate 163/163, paint 768/768 @ 0x003a6ea5, sel4test byte-identical.

## Design
- npfs trampolines + entry run as EXECUTIVE-IMAGE code mapped RWX-shared into npfs's isolated
  VSpace. That stays (it's how shared-code isolation works). "Converge onto the shared surface"
  = (a) the RESOLUTION mechanism comes from nt-compat-exports (a generic heap-free name->VA
  registry, the win32k model), and (b) the trampoline IMPLS are the generic FSD ntoskrnl surface
  (reusable for fastfat), backed by real nt-* logic where pure (prefix-tree already = np_prefix).

## Steps
- [ ] 1. Add generic `DriverExportRegistry` to nt-compat-exports (heap-free name->VA map) + tests.
- [ ] 2. Hoist npfs_host.rs content into driver_launch.rs as the generic FSD-class surface
        (trampolines register into a DriverExportRegistry; fsd_export_addr resolves via it; the
        generic FSD entry + run_irp/dispatch_loop; V_*/SH_*/VA consts as generic FSD facts).
- [ ] 3. load_pe_into binds IAT against the registry resolver.
- [ ] 4. DELETE npfs_host.rs; drop `mod npfs_host`; fix `npfs_host::` refs in main.rs.
- [ ] 5. cargo test the touched crates.
- [ ] 6. build.sh -> build_kernel.sh extern-rootserver -> run_specs.sh; verify gate/paint/npfs/pipe.
- [ ] 7. Commit green; update project_driver_model.md.

## Review — DONE (gate 163/96, 0 FAIL, paint 768/768 @ 0x003a6ea5, exit 3, sel4test byte-identical)
- Added `nt-compat-exports::DriverExportRegistry` (generic heap-free name->VA map, the win32k
  Win32kExportRegistry shape but driver-agnostic) + 4 host tests. THE shared surface any driver's
  IAT binds against.
- Merged npfs_host.rs into driver_launch.rs as the generic FSD-class surface: the ntoskrnl
  trampolines register into an `FSD_EXPORTS: DriverExportRegistry` (register_fsd_trampolines);
  `fsd_export_addr` resolves via it (no hardcoded match). The generic FSD entry is
  `fsd_component_entry` (was npfs_host_entry) + dispatch_loop/run_irp. Consts renamed NPFS_*→FSD_*,
  npfs_host::V_*/SH_*→driver_launch local. Prefix-tree still delegates to nt_kernel_exec::np_prefix.
- DELETED npfs_host.rs; dropped `mod npfs_host`; fixed main.rs `npfs_host::V_*`→`V_*` (glob).
- ZERO rust-micro/src changes → sel4test byte-identical.
- npfs verdict 0x1f, DriverEntry clean (0 faults/0 demand), \ntsvcs create status 0 info=2,
  connect finds FCB — byte-identical to baseline. All 9 npfs specs + live pipe path PASS.
- Reusable for fastfat/next-FSD unchanged. win32k/kmdf trampoline convergence = documented follow-on.
