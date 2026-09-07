//! The generated SEC_IMAGE probe owns only a fault channel and demand-mapped image pages.
//! It must not construct, reset, or consume the live executive's Ps and provider state.

use super::*;

pub(crate) unsafe fn run(
    fault_ep: u64,
    spawn: img_spawn::SecImageSpawn,
    image: nt_exe_image::HostedProcessImageRef<'_>,
    pe: &nt_pe_loader::PeFile,
    scratch_base: u64,
) -> (u64, u64) {
    let reply = alloc_slot();
    assert_ne!(reply, 0, "SEC_IMAGE diagnostic reply reservation failed");
    assert_eq!(
        untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, reply),
        0,
        "SEC_IMAGE diagnostic reply creation failed"
    );
    assert_eq!(
        tcb_resume_r(spawn.main_tcb),
        0,
        "SEC_IMAGE diagnostic resume failed"
    );
    let mut event = recv_full_r12(fault_ep, reply);
    let mut pages = [0u64; 2];
    let mut count = 0usize;
    let mut verdict = 0;
    loop {
        let (badge, info, m0, address, _, _) = event;
        let label = info >> 12;
        let length = info & 0x7f;
        if badge != image.top_badge {
            print_str(b"[sec-image-diagnostic] unexpected fault-channel sender\n");
            break;
        }
        if label == 2 && length == 19 && m0 == SSN_DONE {
            // UnknownSyscall MR9 is the real R10 value read by the generated PE from .rdata.
            verdict = get_recv_mr(9);
            break;
        }
        let page = address & !0xfff;
        if label != 6
            || length != 4
            || count == pages.len()
            || pages[..count].contains(&page)
            || ![PE_LOAD_BASE + 0x1000, PE_LOAD_BASE + 0x2000].contains(&page)
        {
            print_str(b"[sec-image-diagnostic] unexpected fault label=");
            print_u64(label);
            print_str(b" address=0x");
            print_hex_u64(address);
            print_str(b"\n");
            break;
        }

        let scratch = scratch_base + count as u64 * 0x1000;
        assert!(
            ensure_executive_paging(scratch),
            "SEC_IMAGE diagnostic scratch paging failed"
        );
        let (source, allocation_error) = alloc_frame_r();
        assert_eq!(
            allocation_error, 0,
            "SEC_IMAGE diagnostic frame allocation failed"
        );
        assert_ne!(source, 0, "SEC_IMAGE diagnostic frame is absent");
        assert_eq!(
            page_map_r(source, scratch, RW_NX, CAP_INIT_THREAD_VSPACE),
            0,
            "SEC_IMAGE diagnostic scratch mapping failed"
        );
        let rights = fill_image_page(pe, (page - PE_LOAD_BASE) as u32, scratch);
        let (target, copy_error) = copy_cap_r(source);
        assert_eq!(
            copy_error, 0,
            "SEC_IMAGE diagnostic mapping-cap copy failed"
        );
        assert_ne!(target, 0, "SEC_IMAGE diagnostic mapping cap is absent");
        assert_eq!(
            page_map_r(target, page, rights, spawn.pml4),
            0,
            "SEC_IMAGE diagnostic target mapping failed"
        );
        assert!(
            csrss_frame_put_at_cap_source_backing(
                image.pi as u64,
                page,
                target,
                scratch,
                source,
                source,
                true,
                source,
            ),
            "SEC_IMAGE diagnostic frame ownership publication failed"
        );
        pages[count] = page;
        count += 1;
        event = client_reply_recv_badge(fault_ep, reply, 0, 0, 0, 0, 0);
    }
    // Do not resume the sentinel or an unexpected fault. The caller retires the unpublished
    // spawn and its registered frame owners after this bound reply has been detached.
    assert_eq!(
        tcb_suspend_r(spawn.main_tcb),
        0,
        "SEC_IMAGE diagnostic suspend failed"
    );
    assert_eq!(
        cnode_delete_recycle_r(reply),
        0,
        "SEC_IMAGE diagnostic reply retirement failed"
    );
    (verdict, count as u64)
}
