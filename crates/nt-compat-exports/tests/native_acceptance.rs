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
#[path = "native_acceptance/generic_application_contracts.rs"]
mod generic_application_contracts;
#[path = "native_acceptance/image_process_bridge.rs"]
mod image_process_bridge;
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

// Executive globals required by the real cache module exercised in the host harness.
use core::sync::atomic::{AtomicU64, Ordering};
const MAX_PI: usize = 64;
