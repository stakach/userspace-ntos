We're building a reimplementation of the **Windows NT kernel personality in user
space**, running on the [rust-micro](https://github.com/stakach/rust-micro) seL4
microkernel. Using Rust lang.

# Working on this project

We have references for validating behaviour in `./references` make sure to use these when unsure how something should behave.

The key method for NT user mode compatibility is via `ntdll.dll` and we'll use reactos and wine as the primary compatibility goals. Reactos CDs provide our drivers, user space binaries and shell, however we want to improve windows compatibility by implementing everything the wine `ntdll.dll` additionally implements.

Make sure to keep the `README.md` up to date. The `README.md` should be a short overview of the project with details on how to build, run and update the OS, along with the license section.

Keep source code files focused and logically structured. Group by component and split up long files where it makes sense. Files longer than 1000 lines are good targets for splitting but this is not a strict requirement.

## 1. Plan Node Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately, don’t keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

## 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

## 3. Self-Improvement Loop
- After ANY correction from the user, update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

## 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

## 5. Demand Elegance (Balanced)
- For non-trivial changes, pause and ask: "Is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes, don’t over-engineer
- Challenge your own work before presenting it

## 6. Autonomous Bug Fixing
- When given a bug report, don’t ask for hand-holding
- Don’t start by trying to fix it. Instead, start by writing a test that reproduces the bug. Then, have subagents try to fix the bug and prove it by passing that test.
- Point at logs, errors, failing tests, then resolve them
- Zero context switching required from the user

## Task Management

1. **Plan First**: Write the plan to a GitHub issue with checkable items; associate it with its milestone.
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Maintain the issue checklist, native dependencies and status/ownership comments as you go.
4. **Explain Changes**: High-level summary against each commit
5. **Document Results**: Add review section to the pull request
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.

## Kernel Boundaries

- Keep the microkernel small; implement NT policy in the appropriate userspace service and matching `ntdll` contracts.
- Preserve NT semantics. No synthetic success, fallback implementations, or hardcoded process, image, driver, or device identities.
- Discover provider services through registration and metadata. Support multiple drivers and devices without special-case routing.
- Put independently testable behavior in focused crates before native integration.

## IPC and Lifetime Safety

- Retain messages, Replies, capabilities, and continuations across callbacks, waits, faults, and uncertain effects.
- Validate exact physical identity and generation; a badge, message shape, or numeric capability alone is not authority.
- Record ownership before native effects. An uncertain result never permits replay or resource reuse; reply acknowledgement is not provider completion.

## Validation Discipline

- Assign one build/test owner. Never run builds, test suites, image generation, or QEMU validation concurrently against shared artifacts.
- Bound boot attempts to at most one hour; stop stalled runs once their failure is understood. Long intentional uptime is separate.
- Distinguish crate tests, native builds, boot progress, and desktop proof. Dormant adapters are not live integration; desktop claims require genuine Explorer execution and screenshot evidence.

## Progress and Commits

- Keep `docs/kernel-completion-plan.md` current with dependencies, validation evidence, and remaining work; reconcile it with issue tracking.
- Commit verified increments and remove obsolete machinery when its replacement is integrated.
- Preserve independent edits and inspect diffs before committing. Push submodule commits before parent commits that reference them; never claim a clean tree without checking.
