//! A copied native metadata sector must pass the media fence before bypassing SCSI.

const NATIVE_BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");

#[test]
fn native_metadata_hit_completes_the_exact_claim_before_reserving_physical_io() {
    let body = NATIVE_BLOCK
        .split_once("unsafe fn dispatch_claim(")
        .expect("native block dispatcher")
        .1;
    let fence = body.find("fence.eligible(").expect("exact read-through eligibility");
    let hit = body.find("metadata_shadow_for(route).lookup(")
        .expect("copied sector lookup");
    let complete = body.find("claim.complete(Ok(&bytes))")
        .expect("exact cached claim completion");
    let physical = body.find("enter_exec_native_block(")
        .expect("physical block ticket");
    assert!(fence < hit && hit < complete && complete < physical);
    assert!(body.contains("metadata_sector(&claim)"), "only CREATE/DIRECTORY metadata may hit");
}
