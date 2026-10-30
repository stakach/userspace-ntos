use nt_exe_image::service_group_launch::{
    match_declared_group, DeclaredServiceGroup, ForeignInitialThreadEvidence,
};
use nt_exe_image::MAX_COMMAND_LINE;
use nt_memory_manager::{ProcessGeneration, ProcessIdentity, SectionFileIdentity, SectionMountIds};

fn process(pid: u32, generation: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        generation: ProcessGeneration::Hosted(generation),
    }
}

#[test]
fn foreign_initial_thread_matches_only_the_exact_live_scm_group() {
    let mut mounts = SectionMountIds::new();
    let image = SectionFileIdentity {
        mount: mounts.allocate().unwrap(),
        file_id: 71,
    };
    let scm = process(120, 4);
    let child = process(132, 2);
    let declared = DeclaredServiceGroup {
        mount_generation: 8,
        image,
        nt_image_path: b"\\SystemRoot\\System32\\svchost.exe",
        command_line: b"C:\\Windows\\System32\\svchost.exe -k netsvcs",
    };
    let actual = ForeignInitialThreadEvidence {
        caller: scm,
        child,
        mount_generation: 8,
        section_image: image,
        nt_image_path: declared.nt_image_path,
        command_line: declared.command_line,
    };

    let matched = match_declared_group(declared, scm, actual).expect("exact group launch");
    assert_eq!(matched.caller, scm);
    assert_eq!(matched.child, child);
    assert_eq!(matched.mount_generation, 8);

    // A process holding a caller-supplied parent handle for SCM is still not the
    // authenticated syscall caller captured by the initial-thread runtime.
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            caller: process(140, 1),
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            caller: process(120, 3),
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            child: process(132, 0),
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            mount_generation: 7,
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            section_image: SectionFileIdentity {
                file_id: 72,
                ..image
            },
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            nt_image_path: b"\\SystemRoot\\System32\\another.exe",
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            command_line: b"C:\\Windows\\System32\\svchost.exe -k localservice",
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            command_line: b"C:\\Windows\\System32\\svchost.exe -k netsvcs --extra",
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            command_line: b"",
            ..actual
        }
    )
    .is_none());
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            command_line: b"C:\\Windows\\System32\\svchost.exe\0-k netsvcs",
            ..actual
        }
    )
    .is_none());
    let oversized = vec![b'a'; MAX_COMMAND_LINE + 1];
    assert!(match_declared_group(
        declared,
        scm,
        ForeignInitialThreadEvidence {
            command_line: &oversized,
            ..actual
        }
    )
    .is_none());
}
