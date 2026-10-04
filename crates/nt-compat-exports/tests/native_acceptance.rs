#[path = "native_acceptance/dynamic_boot_protocol.rs"]
mod dynamic_boot_protocol;
#[path = "native_acceptance/file_all_owned_fields.rs"]
mod file_all_owned_fields;
#[path = "native_acceptance/kernel_query_seed.rs"]
mod kernel_query_seed;
#[path = "native_acceptance/file_mode_precommit.rs"]
mod file_mode_precommit;
#[path = "native_acceptance/file_mode_set.rs"]
mod file_mode_set;
#[path = "native_acceptance/file_transfer_admission.rs"]
mod file_transfer_admission;
#[path = "native_acceptance/file_query_output_probe.rs"]
mod file_query_output_probe;
#[path = "native_acceptance/file_transfer_input_capture.rs"]
mod file_transfer_input_capture;
#[path = "native_acceptance/generic_application_contracts.rs"]
mod generic_application_contracts;
#[path = "native_acceptance/image_process_bridge.rs"]
mod image_process_bridge;
#[path = "native_acceptance/named_data_sections.rs"]
mod named_data_sections;
#[path = "native_acceptance/directory_security.rs"]
mod directory_security;
#[path = "native_acceptance/thread_construction_failure.rs"]
mod thread_construction_failure;
#[path = "native_acceptance/immediate_iosb_publication.rs"]
mod immediate_iosb_publication;
#[path = "native_acceptance/loaded_image_lifetime.rs"]
mod loaded_image_lifetime;
#[path = "native_acceptance/local_image_section.rs"]
mod local_image_section;
#[path = "native_acceptance/process_terminal_receipt.rs"]
mod process_terminal_receipt;
#[path = "native_acceptance/process_terminal_transition.rs"]
mod process_terminal_transition;
#[path = "native_acceptance/routed_image_capture.rs"]
mod routed_image_capture;
#[path = "native_acceptance/section_cleanup_authority.rs"]
mod section_cleanup_authority;
#[path = "native_acceptance/section_retirement_receipts.rs"]
mod section_retirement_receipts;
extern crate alloc;

#[path = "native_acceptance/client_copy_recorded_backing.rs"]
mod client_copy_recorded_backing;
#[path = "native_acceptance/loader_open_output.rs"]
mod loader_open_output;
#[path = "native_acceptance/pending_file_create_output.rs"]
mod pending_file_create_output;
#[path = "native_acceptance/video_consumer_admission.rs"]
mod video_consumer_admission;
#[path = "native_acceptance/source_completion_lane.rs"]
mod source_completion_lane;
#[path = "native_acceptance/source_pending_retirement.rs"]
mod source_pending_retirement;
#[path = "native_acceptance/mup_read_evidence.rs"]
mod mup_read_evidence;
#[path = "native_acceptance/media_setup_authority.rs"]
mod media_setup_authority;
#[path = "native_acceptance/user_binding_authority.rs"]
mod user_binding_authority;
#[path = "native_acceptance/readonly_file_capacity.rs"]
mod readonly_file_capacity;

// Executive globals required by the real cache module exercised in the host harness.
use core::sync::atomic::{AtomicU64, Ordering};
const MAX_PI: usize = 64;
