//! A classpnp completion can unlock/free its MDL and request IRP free before returning MPR.
//! The retained ticket remains the authority for the later held-completion operation.

use std::process::Command;

#[test]
fn terminal_callback_retains_exact_source_without_requiring_live_children() {
    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let start = ledger.find("fn scsi_after_callback_phase(").expect("post-callback rule");
    let end = start + ledger[start..].find("\npub(super) fn scsi_children_match_after_callback(")
        .expect("exact native identity check");
    let rule = &ledger[start..end];
    syn::parse_str::<syn::ItemFn>(rule).expect("actual native callback phase rule");
    let harness = format!(r#"
mod nt_io_manager {{ pub mod scsi_source_retention {{
    #[derive(Clone, Copy)]
    pub enum ScsiSourcePhase {{ Prepared, Entered, Pending, Uncertain, Terminal,
        SourcePublished,
        ProviderAcknowledged, SourceCompleted, ReadyToRelease }}
}} }}
{rule}
#[test] fn callback_phase() {{
    use nt_io_manager::scsi_source_retention::ScsiSourcePhase::*;
    for phase in [None, Some(Prepared), Some(Entered), Some(Pending), Some(Uncertain)] {{
        assert!(!scsi_after_callback_phase(phase, true));
    }}
    for phase in [Terminal, SourcePublished, ProviderAcknowledged, SourceCompleted, ReadyToRelease] {{
        assert!(scsi_after_callback_phase(Some(phase), true));
        assert!(scsi_after_callback_phase(Some(phase), false),
            "a terminal callback may unlock its source MDL without requesting IRP free");
    }}
}}
"#);
    let directory = std::env::temp_dir().join(format!("nt-scsi-callback-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&source, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&source).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native phase rule: {}",
        String::from_utf8_lossy(&compiled.stderr));
    let run = Command::new(&binary).output().unwrap();
    assert!(run.status.success(), "callback phase behavior: {}",
        String::from_utf8_lossy(&run.stdout));

    let capture = include_str!("../../../components/ntos-executive/src/hosted_scsi_srb_capture.rs");
    let start = capture.find("pub(super) fn validate_retained(&self)").unwrap();
    let end = start + capture[start..].find("\n    /// Re-observe").unwrap();
    let validation = &capture[start..end];
    assert!(validation.contains("scsi_children_match_after_callback("));
    assert!(validation.contains("scsi_children_match_current("));
    assert!(!validation.contains(
        "if hosted_source_irp_ledger::deferred_free_requested(self.ticket) {"
    ), "terminal retained validation must not depend solely on a deferred IRP free request");
    assert!(ledger.contains("scsi_registered_pool_matches_unlocked(inst, children.source)"),
        "callback lookup validates the pinned pool generation after reuse changes the IRP header");
}
