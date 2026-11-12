//! A resumed ServiceWait may encounter a provider wait while another physical lane is active.
//! The labelled Call and its lane-local page own the request and result.

fn source(name: &str) -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src")
            .join(name),
    ).unwrap()
}

#[test]
fn labelled_provider_wait_captures_a_validated_full_request_in_the_pump_result() {
    let pump = source("spawn_hosts.rs");
    let start = pump.find("} else if label == crate::win32k_subsystem::W32_PROVIDER_WAIT_LABEL")
        .expect("provider wait has a labelled Call boundary");
    let end = pump[start..].find("} else if label == crate::win32k_subsystem::W32_LPC_WAIT_LABEL")
        .map(|offset| start + offset)
        .expect("the next labelled Call bounds provider wait handling");
    let labelled_call = &pump[start..end];
    assert!(labelled_call.contains("ProviderWaitRequest")
        && labelled_call.contains(".validate()")
        && labelled_call.contains("outcome.provider_wait_request = Some("),
        "capture and validate the complete request at its exact provider wait Call");

    let outcome = pump.split_once("struct PumpLoopOutcome {")
        .and_then(|(_, rest)| rest.split_once("\n}").map(|(body, _)| body))
        .expect("pump loop outcome exists");
    let result = pump.split_once("pub(crate) struct PumpResult {")
        .and_then(|(_, rest)| rest.split_once("\n}").map(|(body, _)| body))
        .expect("retained pump result exists");
    assert!(outcome.contains("provider_wait_request: Option<nt_provider_wait::ProviderWaitRequest>")
        && result.contains("provider_wait_request: Option<nt_provider_wait::ProviderWaitRequest>"),
        "the labelled request must survive the pump return as a typed retained value");
}

#[test]
fn service_wait_to_provider_uses_its_retained_request_without_reading_the_bank() {
    let receive = source("win32k_receive.rs");
    let start = receive.find("pub(crate) unsafe fn resume_suspended_service_wait_component(")
        .expect("service wait resume exists");
    let end = receive[start..].find("\n}\n")
        .map(|offset| start + offset)
        .expect("service wait resume has a bounded body");
    let resumed = &receive[start..end];
    let provider = resumed.split_once("if let Some(request) = pump.provider_wait_request {")
        .and_then(|(_, rest)| rest.split_once("} else if pump.lpc_wait_suspended {")
            .map(|(body, _)| body))
        .expect("service wait can yield a provider wait");
    assert!(provider.contains("request,")
        && !provider.contains("WIN32K_PROVIDER_WAIT_VADDR")
        && !provider.contains("read_volatile"),
        "the next provider wait must use the request captured at its labelled Call, never a later read of the singleton bank");
}

#[test]
fn provider_wait_request_and_result_are_isolated_by_physical_lane() {
    let layout = source("win32k_subsystem.rs");
    let startup = source("main.rs");
    let pump = source("spawn_hosts.rs");
    let service = source("win32k_receive.rs");

    assert!(layout.contains("PhysicalLanePageLayout")
        && layout.contains("WIN32K_LANE_CAPACITY + 1")
        && layout.contains("provider_wait_page_for_current_lane"),
        "the producer must select a distinct page for each physical lane, including primary");
    assert!(startup.contains("alloc_frame_run(win32k_subsystem::WIN32K_PROVIDER_WAIT_FRAMES)")
        && startup.contains("WIN32K_PROVIDER_WAIT_FRAMES"),
        "both VSpaces must map the entire lane-local provider wait bank");
    for consumer in ["win32k_glue.rs", "service_sec_image.rs",
        "kernel_provider_activation.rs", "kernel_provider_resume.rs"] {
        let body = source(consumer);
        assert!(body.contains("provider_wait_page_for_lane(")
            || body.contains("provider_wait_page_for_channel("),
            "{consumer} must use the exact lane page for results or activation");
    }
    let labelled = pump.split_once("} else if label == crate::win32k_subsystem::W32_PROVIDER_WAIT_LABEL")
        .and_then(|(_, rest)| rest.split_once("} else if label == crate::win32k_subsystem::W32_LPC_WAIT_LABEL")
            .map(|(body, _)| body))
        .expect("provider wait labelled Call boundary");
    assert!(labelled.contains("provider_wait_page_for_channel(ch)")
        && labelled.contains("authenticated_badge(ch, msg.badge)"),
        "capture must read the authenticated caller's lane page, never a shared singleton");
    assert!(labelled.contains("crate::park();")
        && !labelled.contains("outcome.provider_wait_suspended = true;\n                break;"),
        "a refused lane lookup must keep the bound Call and Reply out of ordinary pump completion");
    let resumed = service.split_once("pub(crate) unsafe fn resume_suspended_service_wait_component(")
        .and_then(|(_, rest)| rest.split_once("\n}\n").map(|(body, _)| body))
        .expect("service-wait return boundary");
    assert!(resumed.contains("request.header.owner()")
        && resumed.contains("pending.snapshot.dispatch"),
        "a foreign provider request may not be repackaged under the service-wait owner");
}
