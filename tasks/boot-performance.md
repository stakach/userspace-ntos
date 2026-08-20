# Boot performance: measure, then fix

**Problem reported:** the hosted boot takes ~30 minutes and stalls at the login screen.

Everything below is **measured**, not inferred. Three hypotheses were killed by measurement
before the real cause was found — recorded here so they are not re-investigated.

## Instrumentation added (kept — this is how any future regression gets named)

| Signal | Where | What it answers |
| --- | --- | --- |
| `disk=<cmds>/<sectors>/<Mtick>` in the periodic census | `main.rs` (`AHCI_CMDS`/`AHCI_SECTORS`/`AHCI_TICKS`, gated by `Fat32::census`) | how much wall-clock the AHCI path really costs |
| `exec-dispatch=<calls>/<Mtick>` in the periodic census | `main.rs` (`EXEC_DISPATCH_*`) | executive handler time vs guest time |
| `[census] native-time … top_Mtick: <ssn>=<Mtick>/<calls>` | `print_native_ssn_time` | which syscall costs the time, and per-call |
| `[slow-event] badge=… label=… m0=… took_ms=…` | `service_sec_image.rs` loop top | names any loop iteration >1 s (the log used to just go silent) |
| `[slow-dispatch] #n ssn=… Mtick=…` | `record_native_dispatch_ticks` | names an individual pathological dispatch |

`disk_census_ticks()` uses `rdtsc` (~1 GHz of REAL time under TCG, so 1 Mtick ≈ 1 ms), because
the HPET-based census clock needs a mapping the isolated storage host does not have.

**Landmine found while instrumenting:** the isolated storage host maps its image **read-only**.
Any write to a static from code shared with that host (`fs_loader`, `ahci_*`) faults with no
handler and wedges the boot silently. Counters on shared paths must be gated by a *host-local*
value (`Fat32::census`), never by a static — a static would carry the executive's value if the
image frames are aliased.

## Hypotheses killed by measurement

1. **"The AHCI path is the bottleneck"** (one full port re-init per ≤4 sectors, no block cache).
   Real, ugly, and *not* the problem: measured **871 Mtick ≈ 0.87 s of a 260 s boot** across
   ~14,700 commands (~56 µs each). Left alone deliberately — see "not worth fixing" below.
2. **"The 3 idle APs eat the round-robin TCG budget"** (`-smp 4`, x86-on-arm64 has no MTTCG).
   Killed by A/B: `-smp 1` reproduced the same multi-minute stalls.
3. **"O(n²) directory enumeration"** (`NtQueryDirectoryFile` rescans the whole FAT directory
   twice per call). Real and still true, but it is not on the hot path: total FAT read time is
   inside the 0.87 s above.

## Root causes found and FIXED

### 1. `NtAllocateVirtualMemory` committed page-at-a-time against a linear extent scan

`nt_address_space::VmRegionMap::extent_at` is a linear scan of the whole fixed-capacity extent
array (`VM_REGION_CAPACITY = 96`), and the commit loop called it **twice per 4 KiB page** across
the whole request — including the pages a request does not touch. A large `MEM_RESERVE` commits
nothing yet still paid two full scans per page just to discover it had nothing to do.

Fixed by committing **extent-wise**: advance a run at a time over the longest span where both the
`before` and `after` lookups keep their answer, and do per-page work only inside runs that
actually became committed (or changed protection). Per-page behaviour is identical.

**Measured: SSN 0x12 went from 104,714 Mtick over 2 calls → 8 Mtick over the same 2 calls.**
That is ~105 seconds removed from the boot.

### 2. The 1 kHz kernel tick was costing ~97% of the machine under TCG

The dominant cost. `LAPIC_TIMER_INITIAL_COUNT` was calibrated for a **1 ms** period. Under TCG the
emulated ISR — 15 GPR pushes, `bkl_acquire`, `scheduler.tick()`, `mcs_tick`, and
`swap_iretq_context_if_preempted` — costs a large fraction of a millisecond of *real* time, so the
guest spent most of every period servicing its own clock. Sampling the running vCPU through the
QEMU monitor measured ~85% of it inside interrupt handling and ~11% in user code.

The tick ISR already charges **measured TSC time**, not fire counts, so the period sets
preemption/budget *granularity* only — never how much time is accounted. That makes the rate a
pure cost/granularity trade, and lowering it is semantics-preserving.

`rust-micro/src/arch/x86_64/lapic.rs` now has `LAPIC_TICK_MS`, **gated on `extern-rootserver`**:
10 ms for the hosted NTOS boot, 1 ms everywhere else so the sel4test conformance build stays
byte-identical by construction.

Measured on the same workload shape (~10k dispatches, services.exe hot):

| tick | dispatches | executive time | per dispatch |
| --- | --- | --- | --- |
| 1 ms (before) | 10,241 | 159,967 Mtick | **15.6 ms** |
| 10 ms (chosen) | 10,467 | 4,972 Mtick | **0.475 ms** |
| 200 ms (probe) | 10,043 | 4,211 Mtick | 0.42 ms |

**33× less executive time.** 200 ms buys almost nothing further, so 10 ms is the mildest change
that captures the win.

### 3. A mis-detected "stale" HPET delivery was DROPPING timer wakeups

`delay_timer_delivery_is_stale` treats `counter < comparator` as proof that a delivery belongs to a
previous arm, and the handler then returned **without draining due waiters and without re-arming**.
But the counter is read several instructions after ISR entry, and QEMU's HPET can assert a tick or
so before the read observes the match — so a legitimate one-shot gets discarded and the waiter it
was armed for sleeps until some *unrelated* timer happens to fire.

Measured, repeatedly: `[io-completion] TIMEOUT … deadline=4830460920 now=5676701000` — waiters
woken **~84 seconds past their deadline**, with `TIMER_TICKS_SEEN` advancing by exactly one over
the whole window (i.e. one HPET delivery per ~84 s instead of one per deadline).

The stale path now drains due work and re-arms before returning. Draining is idempotent (nothing
due ⇒ nothing woken) and re-arming restores the one-shot for the earliest remaining deadline, so a
genuinely stale edge costs one wasted scan instead of a lost wakeup. Storm protection is unchanged:
a storming timer still wakes nothing, is still counted, and the guarded rearm still keeps the
comparator ahead of the enable edge.

## Known-real, still open

- **Registry syscalls.** With the 1 kHz tick, a *handful* of early calls carried ~155 s:
  `NtEnumerateKey` 113,995 Mtick over 1057 calls (nearly all of it in the first few),
  `NtOpenKey` 41,441 Mtick over 748 calls, and in another boot `NtEnumerateValueKey`
  152,928 Mtick over 2342 calls. Much of this was tick overhead landing on the slowest handlers,
  so it must be **re-measured against the 10 ms tick** before optimising. Prime suspects if it
  survives: `rebuild_registry_services_order_cache` (walks every service key; `SERVICES_ORDER_REBUILDS`
  counts rebuilds) and `registry_value_by_index_with` (linear scan to the requested index, so a
  full enumeration is O(n²)).
- **★ THE REMAINING DOMINANT COST: an intermittent ~130-160 s whole-machine stall.**
  Single dispatches of *unrelated* syscalls each get charged 130-160 s — `NtCreateKey` 158,950
  Mtick, `NtEnumerateValueKey` 129,904 Mtick, **`NtClose` 160,255 ms**, a win32k SSN 158,753 ms.
  `NtClose` costing 160 s is not compute, and the durations cluster regardless of which handler is
  in flight, so the whole machine stalls and whatever dispatch is open absorbs it.
  Established about it so far:
    * It is **pre-existing** — the same class appears in runs taken before any change here
      (104 s and 113 s dispatches on the unmodified tree), so it is not caused by the tick change.
    * QEMU is pegged at 99% of a host core throughout, and host load is low — the guest really is
      burning the cycles, they are just not going to the executive.
    * `rdtsc` counts real time, so a span that big means the executive thread was either blocked
      inside the handler or **descheduled** while another guest thread ran.
  Next step: profile *during* a stall with the QEMU-monitor sampler (`scratchpad/probe_prof.sh` +
  `sampler2.py`), classifying by symbol into AP-idle / kernel-syscall / kernel-IRQ / user, and
  detect halted vCPUs by an unchanging RIP across consecutive samples — the earlier profile
  mis-classified `rust_syscall_dispatch` as idle and sent the investigation down a blind alley.
- **Boot-path variance.** Runs diverge wildly (some stall in smss, some reach the desktop). Almost
  certainly the same phenomenon as the stall above.

## Deliberately NOT fixed (measured as not worth it)

- AHCI one-port-init-per-command, the 2 KiB DMA window, and the missing block cache: 0.87 s total.
- `NtQueryDirectoryFile`'s double full-directory rescan per call: inside that same 0.87 s.

Both are genuine design debt and should be cleaned up when the disk path matters (persistent
FAT32 write-through), but neither is a boot-time problem today.
