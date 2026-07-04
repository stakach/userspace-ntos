# NT Process Manager (processes, threads, image sections) — compatibility notes

The NT Process Manager (spec: NT Process, Thread, Image Section, and User-Mode Bootstrap).
Process + thread objects, handle tables, and SEC_IMAGE image sections.

## nt-process (implemented, Milestones 26.1-26.4, 26.7)

- Objects (§7): NtProcess (states Created/LoadingImage/Ready/Running/Exiting/Terminated) + NtThread
  (Initialized/Ready/Running/Waiting/Suspended/Terminated) + ClientId {unique_process, unique_thread}.
- Process/thread lifecycle (§9-§11): create_process (own address-space id, optional image section),
  create_thread (first thread → main thread + process Running), set_thread_state transitions.
- Termination + dispatcher signalling (§12.3, §21): terminate_thread (last non-system thread →
  process exit), terminate_process (terminates all threads + releases the image map ref);
  is_process/thread_signaled, wait_process (exit status). System threads don't trigger process exit.
- Handle tables (§8): per-process insert/lookup/close/duplicate_handle (process-local, granted
  access); handles are ×4 (NT convention).
- SEC_IMAGE image sections (§13): create_image_section parses + lays out + relocates a PE via
  nt-pe-loader (entry point, size_of_image), rejects non-PE with STATUS_INVALID_IMAGE_FORMAT.
  Read-only image sharing (§13.7): a second create for the same file reuses the section (map_refs++),
  so two processes reference identical immutable image bytes; terminate releases the ref.
- 6 unit tests: lifecycle + signal, system-thread-doesn't-exit-process, handle table ops, image
  section load+entry (Stage 1), image section shared across processes (Stage 4), invalid image.

## Process/thread lifecycle in QEMU (implemented, Milestone 26 — `configuration-manager`)

The `configuration-manager` component now also proves the process/thread model bare-metal on seL4
(30/30 checks): create a process + its main thread (→ Running), transition thread state, resolve
the Client ID; a per-process handle table where a handle is process-local, duplicates into another
process, and closes; and termination signalling — terminating the last non-system thread exits +
signals the process (wait returns the exit status) and terminates its system thread, leaving an
unrelated process untouched. (Image-section loading is host-tested; nt-pe-loader is already
QEMU-proven by the driver hosts.)
