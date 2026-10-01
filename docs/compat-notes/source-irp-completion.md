# Hosted source IRP completion

Kernel-built IRPs belong to the component that built them. The executive owns
their canonical I/O-manager operation, not the component's private source ledger.
Cross-component traffic uses bounded packets and exact allocation generations;
a raw WDM pointer or Reply acknowledgement is not completion authority.

## Ownership

The origin retains the source IRP, auxiliary buffers, caller targets, completion
Event and request packet before entering the broker. The executive authenticates
the physical lane and device projection, and retains the canonical operation and
native provider resources until strict completion acknowledgement.

For a pending operation, the origin records the returned token before sending an
authenticated pending-armed receipt. Completion delivery waits for that receipt.
Inline and pending delivery are distinct immutable terminal packet properties.
The executive never infers either from a component-private phase or thread state.

## Terminal handoff

1. The executive supplies the exact terminal packet to an authenticated origin
   lane. The origin publishes bounded output and IOSB data but retains backing.
2. After the exact publication acknowledgement, the executive acknowledges the
   canonical operation and reserves a deferred completion-Event state sequence.
3. The origin receives a commit request bound to the same packet and sequence.
   It retires source backing before updating its local Event mirror, releasing
   the Event lease last. The executive commits the canonical Event only after
   the exact origin commit acknowledgement.

The reserved signal is not visible during preparation. A newer Set, Reset,
Clear or consuming wait supersedes an older reservation. Local mirrors also
compare sequences under the component metadata guard: stale observations cannot
overwrite newer state, and contradictory equal-sequence observations are errors.

## Failure and scheduling

Unknown entry or retirement effects retain ownership and forbid replay. A
stopped caller permits discard only at an authenticated broker safe point after
canonical retirement; a stopped TCB or native Reply acknowledgement alone is
insufficient. Discard does not copy into stopped caller targets or signal them.

Nested readiness predicates only inspect exact completed state or immutable,
generation-bound backend readiness. They do not pump the I/O manager, claim
completion, or retry native effects. Effectful progress starts after the parent
execution lane has been parked.
