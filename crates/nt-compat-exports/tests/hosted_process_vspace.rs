//! Execute the actual native journal contract. Fixture caps are metadata only: these tests do
//! not claim kernel allocation, physical VSpace separation, mapping or retirement acknowledgements.
extern crate alloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedThreadRole {
    Main,
}

mod img_spawn {
    #[derive(Clone, Copy)]
    pub(crate) struct HostedProcessVspaceCaps {
        pub generation: u64,
        pub pml4: u64,
        pub image_pdpt: u64,
        pub image_pd: u64,
        pub kuser_pdpt: u64,
        pub kuser_pd: u64,
        pub fault_endpoint: u64,
        pub mapped: [u64; 64],
        pub mapped_len: usize,
        pub mapped_unmapped: u64,
        pub plain: [u64; 16],
        pub plain_len: usize,
    }
}

#[path = "../../../components/ntos-executive/src/hosted_process_vspace.rs"]
mod hosted_process_vspace;

#[test]
fn incomplete_retirement_cannot_drop_the_live_owner() {
    let journal = hosted_process_vspace::HostedProcessVSpaces::new(1);
    let process = nt_memory_manager::ProcessIdentity {
        pid: 304,
        generation: nt_memory_manager::ProcessGeneration::Hosted(2),
    };
    let caps = img_spawn::HostedProcessVspaceCaps {
        generation: 2,
        pml4: 100,
        image_pdpt: 0,
        image_pd: 0,
        kuser_pdpt: 0,
        kuser_pd: 0,
        fault_endpoint: 0,
        mapped: [0; 64],
        mapped_len: 0,
        mapped_unmapped: 0,
        plain: [0; 16],
        plain_len: 0,
    };
    journal.publish(0, process, caps).unwrap();
    let update = journal.begin_update(0, process).unwrap().unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        update.finish_retirement();
    }));
    assert!(failure.is_err());
    assert_eq!(journal.get(0).flatten().unwrap().pml4, 100);
}
