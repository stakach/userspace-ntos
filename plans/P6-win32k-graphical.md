# P6 — win32k.sys Isolated (Graphical) — STUB

**Goal:** run the ReactOS GDI/USER subsystem (**`win32k.sys`**) as an **isolated
component** (not in the microkernel), with a display driver host, reaching a
drawn desktop (`explorer`).

## Status: ~~stub~~ → **DONE (2026-07-14) — the headline: the Windows desktop PAINTS**

### Status (2026-07-14): DONE — real ReactOS win32k.sys hosted, isolated; the desktop paints
The real ReactOS **win32k.sys** is hosted as an **isolated component** with the full
window-manager object graph: real Ob DESKTOP/WINDOWSTATION objects, the WC_DESKTOP class,
the desktop window, the framebuffer display driver + DirectX (dxg/dxgthk) + FreeType
(ftfd/arial.ttf), and the win32k→client **KeUserModeCallback** bridge. It is
**multi-client** (csrss + winlogon as two GUI clients, with per-client cross-AS memory via
attach/detach). **The Windows desktop PAINTS authentically (colour `0x003a6ea5`) via
winlogon's natural `co_IntShowDesktop` → `IntPaintDesktop` flow — no scaffold** — guarded
by a permanent gate spec (commits `25dc18b`, `c3a4266`, `7718304`, `02d011e`, `a66081a`,
`b2e951c`). winlogon.exe runs as the 3rd hosted process to WinMain + the desktop. Run it
with `./run.sh --desktop` to see the pixels. Files: `components/ntos-executive/src/
win32k_host.rs` + `win32k_pe.rs`. **Remaining fidelity work (not blockers):** real
window/input plumbing + the login UI + `explorer`; the GDI-over-SURT perf workstream.

## Sketch
- **The wrinkle:** on NT, `win32k.sys` is kernel-mode with an enormous syscall
  surface (`NtUser*` / `NtGdi*`, thousands of calls). We run it as an **isolated
  component** — truer to the microkernel ideal, but a big surface and a hot path.
- **Approach:** host `win32k.sys` in a dedicated component that owns the framebuffer
  (a display driver host over P1's real MMIO); route `NtUser*`/`NtGdi*` from
  user processes to it over SURT (a second syscall dispatch profile). Incremental:
  bring up the surface calls `explorer` + a basic shell need first, enumerate the
  rest on demand.
- **Display driver:** a framebuffer/VGA or virtio-gpu driver in an isolated host.
- **Performance note:** the GDI hot path over SURT will need batching / shared
  surfaces; treat perf as an explicit workstream.

## Exit criteria
- `explorer` (or a minimal GUI app) draws to the framebuffer via isolated
  `win32k` + a display host. QEMU-verified (screenshot/pixels check).

## E2E test
`e2e-gui`: boot to a drawn desktop or a window; assert a known pixel/region.

## MVP note
A **headless/text server profile** (P0–P5) is a valid product without P6; ship
that first, treat graphical as a follow-on.
