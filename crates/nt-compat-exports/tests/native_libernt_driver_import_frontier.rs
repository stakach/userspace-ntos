//! Released boot drivers define the generic kernel import frontier by exact PE names.

use std::collections::BTreeSet;

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

fn native_imports(driver: &str) -> BTreeSet<String> {
    libernt_driver_imports::imports(driver, &["ntoskrnl.exe", "hal.dll"])
}

#[test]
fn pinned_acpi_imports_native_hal_dispatch_data() {
    assert!(native_imports("acpi.sys").contains("HalPrivateDispatchTable"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("\"HalPrivateDispatchTable\" => FSD_DATA_HAL_PRIVATE_DISPATCH_VA"),
        "generic driver data registry must publish a mapped HAL private dispatch table");
}

#[test]
fn pinned_basicdisplay_imports_terminal_kernel_assertion() {
    assert!(native_imports("basicdisplay.sys").contains("RtlAssert"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\"RtlAssert\","),
        "generic driver registry must bind a source-owned terminal RtlAssert");
}

#[test]
fn pinned_next_imports_bind_real_slist_init_and_driver_unload() {
    assert!(native_imports("acpi.sys").contains("InitializeSListHead"));
    assert!(native_imports("basicdisplay.sys").contains("ZwUnloadDriver"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for name in ["InitializeSListHead", "ZwUnloadDriver"] {
        assert!(source.contains(&format!("\"{name}\",")), "generic export registry lacks {name}");
    }
    let loader = include_str!("../../../components/ntos-executive/src/hosted_zw_load_driver.rs");
    assert!(loader.contains("unload_driver_by_name"), "ZwUnloadDriver must reach canonical driver lifecycle");
}

#[test]
fn pinned_acpi_interrupt_ex_uses_the_existing_grant_owned_connection() {
    assert!(native_imports("acpi.sys").contains("IoConnectInterruptEx"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"IoConnectInterruptEx\","),
        "generic registry must expose the released ACPI import");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_interrupt_ex.rs");
    assert!(adapter.contains("s_io_connect_interrupt(") && adapter.contains("SH_RESOURCE_PDO_OBJECT"),
        "extended interrupt connection must reach the grant-owned broker path");
}

#[test]
fn pinned_dxgkrnl_previous_mode_reads_the_current_thread_projection() {
    assert!(native_imports("dxgkrnl.sys").contains("ExGetPreviousMode"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"ExGetPreviousMode\","),
        "generic registry must expose the released dxgkrnl import");
    let mode = include_str!("../../../components/ntos-executive/src/hosted_io_create_file_adapter.rs");
    assert!(mode.contains("current_ps_value(3)") && mode.contains("KTHREAD_PREVIOUS_MODE"),
        "generic PreviousMode must come from the selected thread projection");
}

#[test]
fn pinned_acpi_interrupt_ex_disconnect_retires_the_grant_owned_projection() {
    assert!(native_imports("acpi.sys").contains("IoDisconnectInterruptEx"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"IoDisconnectInterruptEx\","),
        "generic registry must expose the released ACPI disconnect import");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_interrupt_ex.rs");
    assert!(adapter.contains("s_io_disconnect_interrupt(") && adapter.contains("s_io_disconnect_interrupt_ex"),
        "extended disconnect must retire the existing root-owned connection");
}

#[test]
fn pinned_dxgkrnl_uuid_uses_root_owned_generation() {
    assert!(native_imports("dxgkrnl.sys").contains("ExUuidCreate"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"ExUuidCreate\","),
        "generic registry must expose the released dxgkrnl UUID import");
    assert!(source.contains("FSD_SERVICE_UUID_CREATE_LABEL"),
        "UUID allocation must be root-owned across driver VSpaces");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    assert!(pump.contains("msg.mi == (crate::driver_launch::FSD_SERVICE_UUID_CREATE_LABEL << 12)"),
        "UUID service must reject malformed message length before allocation");
}

#[test]
fn pinned_acpi_device_enumeration_retains_returned_objects() {
    assert!(native_imports("acpi.sys").contains("IoEnumerateDeviceObjectList"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"IoEnumerateDeviceObjectList\","),
        "generic registry must expose released ACPI enumeration import");
    assert!(source.contains("s_obf_reference_object("),
        "each published device pointer needs a canonical counted reference");
}

#[test]
fn pinned_dxgkrnl_push_lock_uses_live_waiter_semantics() {
    assert!(native_imports("dxgkrnl.sys").contains("ExfAcquirePushLockExclusive"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"ExfAcquirePushLockExclusive\","),
        "generic registry must expose released dxgkrnl push lock import");
    assert!(source.contains("hosted_driver_push_lock::acquire_exclusive"),
        "generic push lock must use the NT lock policy and wait path");
}

#[test]
fn pinned_acpi_interface_query_uses_cm_and_exact_pdo_identity() {
    assert!(native_imports("acpi.sys").contains("IoGetDeviceInterfaces"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"IoGetDeviceInterfaces\","),
        "generic registry must expose released ACPI interface query");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_device_interfaces.rs");
    assert!(adapter.contains("INTERFACE_LINKS") && adapter.contains("authenticated_hosted_pdo"),
        "query must use CM interface snapshot and canonical PDO identity");
    assert!(adapter.contains("pool_alloc") && adapter.contains("encode_utf16"),
        "the MULTI_SZ result must live in the caller's component pool");
}

#[test]
fn pinned_dxgkrnl_gop_query_uses_captured_boot_framebuffer() {
    assert!(native_imports("dxgkrnl.sys").contains("InbvGetGopFrameBufferInfo"));
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(source.contains("reg.bind(\n        \"InbvGetGopFrameBufferInfo\","),
        "generic registry must expose released dxgkrnl GOP query");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_gop.rs");
    assert!(adapter.contains("FrameBufferBase") && adapter.contains("PixelsPerScanLine"),
        "the output must match LiberNT's LOADER_PARAMETER_FRAMEBUFFER ABI");
    assert!(adapter.contains("FB_BAR_PADDR") && adapter.contains("FB_SCANOUT_BAR_OFFSET"),
        "GOP data must derive from the mapped boot framebuffer BAR");
}

#[test]
fn interface_query_transfer_blocks_driver_retirement_until_owner_releases_it() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let query = include_str!("../../../components/ntos-executive/src/hosted_driver_device_interfaces.rs");
    assert!(launch.contains("hosted_driver_device_interfaces::transfers_quiesced(domain)"),
        "an outstanding banked interface query must block provider lifetime retirement");
    assert!(launch.contains("hosted_driver_device_interfaces::retire_domain(domain)"),
        "stopped provider teardown must release retained query snapshots");
    assert!(query.contains("row.owner == owner && row.token == arg2"),
        "pull and abort must match exact owner and monotonic token");
    assert!(query.contains("instance_path(owner).as_deref() != Ok(instance.as_str())"),
        "the original PDO incarnation must still own the snapshot before publication");
}

#[test]
fn pinned_acpi_devprop_driver_key_uses_canonical_pdo_and_cm_value() {
    assert!(native_imports("acpi.sys").contains("IoGetDevicePropertyData"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoGetDevicePropertyData\","),
        "generic registry must expose released ACPI property query");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_device_property_data.rs");
    assert!(adapter.contains("DEVPKEY_Device_Driver") && adapter.contains("DRIVER_KEY_NAME"),
        "the queried DEVPROPKEY must resolve the CM-owned driver key, not a fabricated value");
    let transfer = include_str!("../../../components/ntos-executive/src/device_property.rs");
    assert!(adapter.contains("device_property::query")
        && launch.contains("authenticated_hosted_pdo")
        && transfer.contains("config_device_property_snapshot"),
        "the shared query must validate its exact PDO and read the canonical configuration snapshot");
}

#[test]
fn pinned_dxgkrnl_gop_validity_reuses_captured_boot_record() {
    assert!(native_imports("dxgkrnl.sys").contains("InbvHasValidGopFrameBuffer"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"InbvHasValidGopFrameBuffer\","),
        "generic registry must expose released dxgkrnl validity query");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_gop.rs");
    assert!(adapter.contains("s_inbv_has_valid_gop_frame_buffer")
        && adapter.contains("s_inbv_get_gop_frame_buffer_info"),
        "validity must derive from the same authenticated captured GOP record");
}

#[test]
fn pinned_acpi_pnp_notification_retains_exact_registration_and_delivers_arrival() {
    let imports = native_imports("acpi.sys");
    assert!(imports.contains("IoRegisterPlugPlayNotification"));
    assert!(imports.contains("IoUnregisterPlugPlayNotification"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoRegisterPlugPlayNotification\","));
    assert!(launch.contains("reg.bind(\n        \"IoUnregisterPlugPlayNotification\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pnp_notification.rs");
    assert!(adapter.contains("set_hosted_device_interface_state")
        && adapter.contains("GUID_DEVICE_INTERFACE_ARRIVAL")
        && adapter.contains("dispatch_device_projection_control_for_instance"),
        "real interface activation must reach an authenticated provider callback");
    assert!(adapter.contains("retire_domain") && adapter.contains("unregister"),
        "notification cookies and callbacks must have a driver-domain retirement path");
}

#[test]
fn pinned_dxgkrnl_display_handoff_changes_root_boot_display_state() {
    assert!(native_imports("dxgkrnl.sys").contains("InbvNotifyDisplayOwnershipLost"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"InbvNotifyDisplayOwnershipLost\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_gop.rs");
    assert!(adapter.contains("s_inbv_notify_display_ownership_lost")
        && adapter.contains("DISPLAY_OWNERSHIP_LOST")
        && adapter.contains("service_hosted_driver_display_ownership_lost"),
        "selected postdisplay handoff must latch an authenticated root ownership transition");
}

#[test]
fn pinned_acpi_device_property_write_uses_exact_pdo_and_cm_owner() {
    assert!(native_imports("acpi.sys").contains("IoSetDevicePropertyData"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoSetDevicePropertyData\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_device_property_write.rs");
    assert!(adapter.contains("DEVPKEY_DEVICE_BUS_NUMBER")
        && adapter.contains("DEVPKEY_DEVICE_ADDRESS")
        && adapter.contains("DEVPKEY_DEVICE_FRIENDLY_NAME"),
        "the pinned ACPI PDO writes require their actual typed keys");
    let cm = include_str!("../../nt-config-server/src/devprop_set.rs");
    assert!(adapter.contains("authenticated_hosted_pdo")
        && adapter.contains("config_manager_set_device_devprop")
        && cm.contains("assign_devprop"),
        "property writes must bind a live PDO incarnation to the CM owner");
}

#[test]
fn pinned_dxgkrnl_create_driver_observes_existing_canonical_name() {
    assert!(native_imports("dxgkrnl.sys").contains("IoCreateDriver"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoCreateDriver\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_create_driver.rs");
    assert!(adapter.contains("driver_id_by_name")
        && adapter.contains("OBJECT_NAME_COLLISION")
        && adapter.contains("STATUS_NOT_SUPPORTED"),
        "the pinned named call must observe the already published canonical driver; fresh creation cannot claim success");
}

#[test]
fn pinned_acpi_thermal_mask_tracks_boot_processor_authority() {
    assert!(native_imports("acpi.sys").contains("KeQueryActiveProcessors"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"KeQueryActiveProcessors\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_processor_mask.rs");
    assert!(adapter.contains("SYSTEM_PROCESSOR_COUNT")
        && adapter.contains("active_processor_mask"),
        "ACPI thermal mask must derive from the boot processor authority");
}

#[test]
fn pinned_dxgkrnl_device_state_invalidation_queries_canonical_pdo() {
    assert!(native_imports("dxgkrnl.sys").contains("IoInvalidateDeviceState"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoInvalidateDeviceState\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_device_state.rs");
    assert!(adapter.contains("authenticated_hosted_pdo")
        && adapter.contains("IRP_MN_QUERY_PNP_DEVICE_STATE")
        && adapter.contains("retire_domain"),
        "invalidation must retain exact PDO and driver-domain ownership through a real PnP state query");
}

#[test]
fn pinned_acpi_thermal_request_requires_real_target_and_policy_owner() {
    assert!(native_imports("acpi.sys").contains("PoCreateThermalRequest"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"PoCreateThermalRequest\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_thermal_request.rs");
    assert!(adapter.contains("STATUS_NOT_SUPPORTED")
        && adapter.contains("PoCreateThermalRequest")
        && adapter.contains("PoGetThermalRequestSupport"),
        "no thermal request may claim success without a processor/policy provider");
}

#[test]
fn pinned_dxgkrnl_wow64_check_uses_exact_process_architecture_proof() {
    assert!(native_imports("dxgkrnl.sys").contains("IoIs32bitProcess"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoIs32bitProcess\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_process_bitness.rs");
    assert!(launch.contains("process_wow64_pointer")
        && launch.contains("original_thread")
        && adapter.contains("provider_bugcheck"),
        "the pinned NULL-IRP path must use the actual caller process and reject unsupported IRP provenance");
}

#[test]
fn pinned_acpi_rtl_char_integer_uses_shared_nt_parser() {
    assert!(native_imports("acpi.sys").contains("RtlCharToInteger"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"RtlCharToInteger\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_rtl_integer.rs");
    assert!(adapter.contains("nt_compat_exports::rtl::char_to_integer")
        && adapter.contains("STATUS_INVALID_PARAMETER")
        && adapter.contains("STATUS_ACCESS_VIOLATION"),
        "the kernel export must reuse native RTL parsing and preserve parameter status");
}

#[test]
fn pinned_dxgkrnl_notification_ex_waits_for_callback_quiescence() {
    assert!(native_imports("dxgkrnl.sys").contains("IoUnregisterPlugPlayNotificationEx"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"IoUnregisterPlugPlayNotificationEx\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pnp_notification.rs");
    assert!(adapter.contains("fn unregister_ex")
        && adapter.contains("EventState::Executing")
        && adapter.contains("NtStatus::DEVICE_BUSY"),
        "Ex unregister must not acknowledge while an irreversible callback remains executing");
}

#[test]
fn pinned_acpi_snwprintf_uses_bounded_utf16_varargs_gate() {
    assert!(native_imports("acpi.sys").contains("_snwprintf"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\"_snwprintf\", hosted_snwprintf_gate")
        && launch.contains("fn hosted_snwprintf_gate();")
        && launch.contains("format_wide_driver(dst, count, fmt, &mut args)"),
        "the released ACPI CRT import must use Win64 variadic capture and bounded wide output");
}

#[test]
fn pinned_dxgkrnl_debugger_presence_reads_component_data_byte() {
    assert!(native_imports("dxgkrnl.sys").contains("KdDebuggerNotPresent"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("\"KdDebuggerNotPresent\" => FSD_DATA_KD_DEBUGGER_NOT_PRESENT_VA")
        && launch.contains("FSD_DATA_KD_DEBUGGER_NOT_PRESENT_OFF")
        && launch.contains("kd_debugger_not_present as *mut u8")
        && launch.contains("kernel_debugger_connected"),
        "IAT data import must name an initialized BOOLEAN in the isolated driver VSpace");
}

#[test]
fn pinned_acpi_underscored_wide_printf_reuses_win64_variadic_gate() {
    assert!(native_imports("acpi.sys").contains("_swprintf"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\"_swprintf\", hosted_swprintf_gate"),
        "the underscore CRT spelling must retain the existing wide Win64 argument contract");
}

#[test]
fn pinned_dxgkrnl_in_stack_queued_lock_retains_handle_and_irql() {
    let imports = native_imports("dxgkrnl.sys");
    assert!(imports.contains("KeAcquireInStackQueuedSpinLock"));
    assert!(imports.contains("KeReleaseInStackQueuedSpinLock"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for name in ["KeAcquireInStackQueuedSpinLock", "KeReleaseInStackQueuedSpinLock"] {
        assert!(launch.contains(&format!("\"{name}\",")), "generic registry lacks {name}");
    }
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_queued_spin_lock.rs");
    assert!(adapter.contains("queued_spin_lock::try_acquire")
        && adapter.contains("queued_spin_lock::release")
        && adapter.contains("hosted_raise_irql(DISPATCH_LEVEL)")
        && adapter.contains("hosted_lower_irql(old_irql)")
        && adapter.contains("LOCK_HANDLE_OLD_IRQL_OFF"),
        "queue handle must own actual atomic exclusion and restore its saved IRQL");
}

#[test]
fn pinned_acpi_memchr_reuses_bounded_crt_search() {
    assert!(native_imports("acpi.sys").contains("memchr"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\"memchr\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_crt_memchr.rs");
    assert!(adapter.contains("nt_compat_exports::crt::memchr")
        && adapter.contains("from_raw_parts")
        && adapter.contains("checked_add"),
        "search must stay inside the exact caller-supplied byte count");
}

#[test]
fn pinned_dxgkrnl_cache_invalidation_flushes_each_coherent_line() {
    assert!(native_imports("dxgkrnl.sys").contains("KeInvalidateRangeAllCaches"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"KeInvalidateRangeAllCaches\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_cache_invalidation.rs");
    assert!(adapter.contains("cache_invalidation::cache_lines")
        && adapter.contains("clflush")
        && adapter.contains("mfence")
        && adapter.contains("__cpuid")
        && adapter.contains("provider_bugcheck"),
        "void cache invalidation must complete real CPU-coherent line flushes before return");
}

#[test]
fn pinned_acpi_strchr_uses_shared_crt_nul_search() {
    assert!(native_imports("acpi.sys").contains("strchr"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\"strchr\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_crt_strchr.rs");
    assert!(adapter.contains("nt_compat_exports::crt::strchr")
        && adapter.contains("checked_add")
        && adapter.contains("MAX_CSTRING_BYTES"),
        "the search must include the first terminator and preserve exact pointer bounds");
}

#[test]
fn pinned_dxgkrnl_thread_priority_reuses_native_tcb_owner() {
    assert!(native_imports("dxgkrnl.sys").contains("KeSetPriorityThread"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"KeSetPriorityThread\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_thread_priority.rs");
    let owner = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    assert!(owner.contains("service_hosted_driver_thread_priority")
        && owner.contains("native_thread_priority::dispatch")
        && adapter.contains("hosted_driver_caller")
        && adapter.contains("provider_registry_caller::resolve")
        && adapter.contains("provider_bugcheck"),
        "priority must use the exact caller and PM/TCB effect owner, returning the previous priority");
}

#[test]
fn pinned_dxgkrnl_system_worker_priority_owns_its_own_ethread_and_tcb() {
    assert!(native_imports("dxgkrnl.sys").contains("KeSetPriorityThread"));
    let actor = include_str!("../../../components/ntos-executive/src/hosted_thread_resources.rs");
    assert!(actor.contains("pm.create_thread(")
        && actor.contains("publish_system_worker")
        && actor.contains("initialize_kpcr"),
        "PsCreateSystemThread already gives each worker a canonical ETHREAD");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_thread_priority.rs");
    let worker = include_str!("../../../components/ntos-executive/src/hosted_driver_worker_priority.rs");
    assert!(adapter.contains("hosted_driver_worker_priority::dispatch")
        && worker.contains("hosted_thread_resources::prepare_priority")
        && worker.contains("tcb_set_priority_r")
        && worker.contains("hosted_thread_resources::commit_priority")
        && actor.contains("prepare_kernel_thread_priority")
        && actor.contains("commit_kernel_thread_priority_retained")
        && actor.contains("priority_plan.is_some()"),
        "worker priority must change its own retained PM state and physical TCB, returning the old value");
}

#[test]
fn pinned_acpi_hal_idt_conversion_uses_registered_interrupt_authority() {
    assert!(native_imports("acpi.sys").contains("HalConvertDeviceIdtToIrql"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"HalConvertDeviceIdtToIrql\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_hal_idt_irql.rs");
    assert!(adapter.contains("SH_RESOURCE_INTERRUPT_VECTOR")
        && adapter.contains("SH_RESOURCE_INTERRUPT_POLICY")
        && adapter.contains("provider_bugcheck"),
        "the conversion must use the admitted interrupt vector/IRQL mapping");
}

#[test]
fn pinned_dxgkrnl_stack_attach_preserves_target_and_detach_ownership() {
    assert!(native_imports("dxgkrnl.sys").contains("KeStackAttachProcess"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"KeStackAttachProcess\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_process_attach.rs");
    assert!(adapter.contains("KeUnstackDetachProcess")
        && adapter.contains("provider_registry_caller::resolve")
        && adapter.contains("hosted_driver_caller")
        && adapter.contains("provider_bugcheck"),
        "attach/detach must be paired to an exact physical thread and target process");
}

#[test]
fn pinned_acpi_hal_target_information_uses_real_processor_topology() {
    assert!(native_imports("acpi.sys").contains("HalGetInterruptTargetInformation"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"HalGetInterruptTargetInformation\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_hal_target_info.rs");
    assert!(adapter.contains("HAL_INTERRUPT_TARGET_INFORMATION_VERSION")
        && adapter.contains("hosted_driver_processor_mask::active_processor_mask")
        && adapter.contains("DestinationId")
        && adapter.contains("ProcessorNumber"),
        "the released ACPI one-argument ABI requires checked version, affinity and real target ID");
}

#[test]
fn pinned_dxgkrnl_try_spin_lock_shares_acquire_release_state() {
    assert!(native_imports("dxgkrnl.sys").contains("KeTryToAcquireSpinLockAtDpcLevel"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for name in [
        "KeAcquireSpinLockRaiseToDpc", "KeReleaseSpinLock",
        "KeAcquireSpinLockAtDpcLevel", "KeReleaseSpinLockFromDpcLevel",
        "KeTryToAcquireSpinLockAtDpcLevel",
    ] {
        assert!(launch.contains(&format!("\"{name}\"")));
    }
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_spin_lock.rs");
    assert!(adapter.contains("compare_exchange")
        && adapter.contains("hosted_current_irql")
        && adapter.contains("provider_bugcheck")
        && adapter.contains("try_acquire"),
        "try must observe the same lock word and IRQL as all native acquire/release variants");
}

#[test]
fn pinned_dxgkrnl_crt_sort_and_wide_search_use_shared_source_semantics() {
    let imports = native_imports("dxgkrnl.sys");
    for name in ["qsort", "wcscmp", "wcsrchr"] {
        assert!(imports.contains(name), "pinned dxgkrnl lacks expected {name}");
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for name in ["qsort", "wcscmp", "wcsrchr"] {
        assert!(launch.contains(&format!("reg.bind(\"{name}\",")), "missing generic {name}");
    }
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_crt_wide_sort.rs");
    assert!(adapter.contains("nt_compat_exports::crt::compare_wide_z")
        && adapter.contains("nt_compat_exports::crt::rfind_wide_z")
        && adapter.contains("nt_compat_exports::crt::sort_opaque_elements")
        && adapter.contains("checked_mul")
        && adapter.contains("provider_bugcheck"),
        "native CRT wrappers must share bounded, checked ntdll semantics");
}

#[test]
fn pinned_acpi_hal_cache_query_checks_owned_physical_range() {
    assert!(native_imports("acpi.sys").contains("HalGetMemoryCachingRequirements"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"HalGetMemoryCachingRequirements\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_hal_cache.rs");
    assert!(adapter.contains("find_shared_address_resource_by_range")
        && adapter.contains("MM_NON_CACHED")
        && adapter.contains("STATUS_NOT_SUPPORTED"),
        "only an owned physical grant may claim a caching policy");
}

#[test]
fn pinned_dxgkrnl_physical_mdl_has_real_pfn_and_release_ownership() {
    assert!(native_imports("dxgkrnl.sys").contains("MmAllocatePagesForMdlEx"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"MmAllocatePagesForMdlEx\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_physical_mdl.rs");
    assert!(adapter.contains("hosted_component_physical_address")
        && adapter.contains("MDL_PAGES_LOCKED")
        && adapter.contains("checked_mul")
        && adapter.contains("MmFreePagesFromMdl")
        && adapter.contains("pool_free"),
        "MDL allocation must retain physical pages and a matching release path");
}

#[test]
fn pinned_dxgkrnl_create_mdl_allocates_exact_header_and_pfn_capacity() {
    assert!(native_imports("dxgkrnl.sys").contains("MmCreateMdl"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"MmCreateMdl\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_create_mdl.rs");
    assert!(adapter.contains("nt_mdl::MDL_OFF_SIZE")
        && adapter.contains("nt_mdl::MDL_OFF_START_VA")
        && adapter.contains("nt_mdl::create_mdl::mdl_size_for_range")
        && adapter.contains("pool_alloc")
        && adapter.contains("component_pool_allocation_capacity"),
        "MmCreateMdl must allocate the PFN-sized MDL and initialize its exact x64 header");
}

#[test]
fn pinned_acpi_pci_root_configuration_has_a_real_provider_ledger() {
    assert!(native_imports("acpi.sys").contains("HalpConfigurePciRootBridge"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"HalpConfigurePciRootBridge\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pci_root.rs");
    assert!(adapter.contains("HAL_ACPI_PCI_ROOT_INFO")
        && adapter.contains("BusRangePresent")
        && adapter.contains("MemoryWindow")
        && adapter.contains("provider_bugcheck"),
        "VOID HAL import must publish validated PCI-root authority or terminate");
}

#[test]
fn pinned_acpi_pci_route_query_retains_exact_callback_image() {
    assert!(native_imports("acpi.sys").contains("HalpRegisterPciRouteQuery"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"HalpRegisterPciRouteQuery\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pci_route_query.rs");
    assert!(adapter.contains("published_image_for_callback")
        && adapter.contains("PciRouteCallbackLedger")
        && adapter.contains("blocks_instance_retirement")
        && adapter.contains("provider_bugcheck"));
}

#[test]
fn pinned_dxg_contiguous_release_uses_exact_physical_allocation_owner() {
    assert!(native_imports("dxgkrnl.sys").contains("MmFreeContiguousMemory"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"MmFreeContiguousMemory\","));
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_contiguous_memory.rs");
    assert!(adapter.contains("validate_page_run")
        && adapter.contains("hosted_component_physical_address")
        && adapter.contains("pool_free")
        && adapter.contains("provider_bugcheck"));
}

#[test]
fn pinned_dxg_physical_memory_ranges_copy_boot_ram_and_terminate() {
    assert!(native_imports("dxgkrnl.sys").contains("MmGetPhysicalMemoryRanges"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"MmGetPhysicalMemoryRanges\","));
    let adapter = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/hosted_driver_physical_ranges.rs"
    ))
    .expect("the native physical memory range adapter must exist");
    assert!(adapter.contains("loader_firmware_memory_map")
        && adapter.contains("pool_alloc")
        && adapter.contains("pool_free")
        && adapter.contains("physical_memory_ranges_from_firmware"),
        "caller-owned array must copy boot-proven RAM and end in a zero pair");
}
