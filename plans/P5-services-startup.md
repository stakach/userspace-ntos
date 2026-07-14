# P5 — Services & Registry-Driven Startup — STUB

**Goal:** run ReactOS **`services.exe`** (the Service Control Manager) so it reads
the registry and starts drivers/services, with our **PnP Manager + I/O Manager +
`nt-driver-supervisor`** hosting the drivers as isolated processes.

## Status: **NOT STARTED (2026-07-14)** — the frontier of the natural boot flow

### Status (2026-07-14): NOT STARTED
services.exe (the SCM), lsass, and the login/GINA path are **not begun**. This is now
the natural next step *beyond winlogon* in the ReactOS boot chain: winlogon already runs
to WinMain + a painted desktop (P6), so continuing the authentic flow means bringing up
the SCM to read `\...\Services` and start a driver/service. Readiness is high — the
driver-hosting machinery (WDM/KMDF isolated hosts + `nt-driver-supervisor`), the PnP/Io
managers, `nt-security`, and live registry reads (`nt-hive-regf`) all exist. See the
next-step candidates in PLAN.md §10 (2026-07-14).

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
