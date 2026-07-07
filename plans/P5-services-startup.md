# P5 — Services & Registry-Driven Startup — STUB

**Goal:** run ReactOS **`services.exe`** (the Service Control Manager) so it reads
the registry and starts drivers/services, with our **PnP Manager + I/O Manager +
`nt-driver-supervisor`** hosting the drivers as isolated processes.

## Status: stub (expand when P4 nears exit)

## Sketch
- **SCM:** `services.exe` enumerates `\Registry\Machine\System\CurrentControlSet\
  Services`, honoring `Start` (boot/system/auto/demand/disabled — where our
  supervisor already writes `Start=4` on crash-loop) and `Type` (kernel driver
  vs. service).
- **Driver start path:** for kernel drivers, SCM → I/O Manager → PnP → an isolated
  **driver host** (reuse the KMDF/WDM/UMDF v2 hosting + supervisor). Real ReactOS
  drivers load from the volume.
- **Service start path:** user-mode services as processes (P3 machinery), each
  talking to the executive via native calls / LPC.
- **Security:** real tokens/SIDs/ACL checks on the start path; `lsass` for
  authentication as needed. (`nt-security` exists.)

## Exit criteria
- SCM boots from the registry and starts at least one real driver (isolated,
  supervised) and one user-mode service, honoring `Start`/`Type`. QEMU-verified.

## E2E test
`e2e-scm`: boot with a registry that declares a demo driver + service → SCM starts
both → assert the driver is hosted (isolated) and the service responds.
