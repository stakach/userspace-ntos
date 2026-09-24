# Native Mup Provider Fixture

`build.sh` prepares a PE32+ WDM driver without CRT or private executive imports. It does not stage or run the driver. `DriverEntry` creates `\\Device\\NtosUncProbe`, opens `\\Device\\Mup`, and sends ReactOS's `FSCTL_MUP_REGISTER_PROVIDER` with the provider device name. It retains the Mup handle until unload. Mup must open the provider device through ordinary object/file routing before it can register it.

For `IOCTL_REDIR_QUERY_PATH`, the fixture accepts only the `\\ntos-probe` server prefix with a retained security context, returns its UTF-16 byte length in `QUERY_PATH_RESPONSE`, and completes the actual IRP. Other names are rejected. Only the provider device's root CREATE succeeds; subsequent rerouted path CREATEs fail because this fixture has no filesystem backend. `MupProviderEvidence` is exported for gate inspection; `DbgPrint` emits registration and accepted-query records.

The native gate must load Mup and this fixture, then open a `\\ntos-probe\\share` UNC path through Mup to trigger a query. A successful registration log alone is not forwarding proof. The gate should check an accepted query in this provider and Mup's own query completion, including exact source/target IRP identity and one terminal completion. The follow-on rerouted CREATE is intentionally not implemented as a filesystem operation by this fixture.

The current executive export table lacks `ZwFsControlFile` and `ZwWaitForSingleObject` bindings for hosted driver imports. Integrate those with genuine NT semantics before staging this fixture. It also needs the normal `ZwCreateFile`, routed device open, `IofCompleteRequest`, and unload paths; do not special-case this driver's name or UNC prefix in the executive.
