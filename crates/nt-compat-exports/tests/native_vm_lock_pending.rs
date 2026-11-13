//! Native VM lock must retain its syscall Reply while mapped or image page reads pend.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const LOCK: &str = include_str!("../../../components/ntos-executive/src/vm_lock_pagein_work.rs");
const SECTION: &str = include_str!("../../../components/ntos-executive/src/section_pagein_work.rs");
const IMAGE: &str = include_str!("../../../components/ntos-executive/src/native_image_pagein_work.rs");

#[test]
fn vm_lock_enters_one_retained_reply_before_any_routed_page_effect() {
    assert!(SERVICE.contains("vm_lock_pagein_work::submit("));
    assert!(LOCK.contains("RootReplyPark::prepare()"));
    assert!(LOCK.contains("VmLockPageContinuation"));
    assert!(LOCK.contains("section_pagein_work::submit_for_vm_lock("));
    assert!(LOCK.contains("native_image_pagein_work::submit_for_vm_lock("));
    assert!(SECTION.contains("vm_lock_pagein_work::page_completed("));
    assert!(IMAGE.contains("vm_lock_pagein_work::page_completed("));
    assert!(LOCK.contains("vm_page_lock_range("));
    assert!(LOCK.contains("reply_parked_syscall("));
}
