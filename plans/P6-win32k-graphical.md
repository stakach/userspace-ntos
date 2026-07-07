# P6 — win32k.sys Isolated (Graphical) — STUB

**Goal:** run the ReactOS GDI/USER subsystem (**`win32k.sys`**) as an **isolated
component** (not in the microkernel), with a display driver host, reaching a
drawn desktop (`explorer`).

## Status: stub (large; optional for a headless/text-server MVP)

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
