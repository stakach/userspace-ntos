//! Checked caller-memory admission and bounded rejection diagnostics for video miniports.

use super::*;
use nt_video_miniport::caller_memory::{
    CallerMemoryGrant, CallerMemoryRejection, CallerMemoryRequest,
};

static REJECTIONS: AtomicU32 = AtomicU32::new(0);

pub(super) unsafe fn caller_va(start: u64, len: u64) -> Option<u64> {
    let grant = CallerMemoryGrant {
        physical: read_volatile((FSD_SHARED_VADDR + SH_VIDEO_MEMORY_PHYS) as *const u64),
        length: read_volatile((FSD_SHARED_VADDR + SH_VIDEO_MEMORY_LEN) as *const u64),
        caller_va: read_volatile((FSD_SHARED_VADDR + SH_VIDEO_MEMORY_CALLER_VA) as *const u64),
    };
    let request = CallerMemoryRequest {
        physical: start,
        length: len,
    };
    match nt_video_miniport::caller_memory::admit_caller_memory(
        grant,
        request,
        hosted_memory_range_granted(start, len),
    ) {
        Ok(address) => Some(address),
        Err(reason) => {
            report_rejection(grant, request, reason);
            None
        }
    }
}

unsafe fn report_rejection(
    grant: CallerMemoryGrant,
    request: CallerMemoryRequest,
    reason: CallerMemoryRejection,
) {
    if REJECTIONS.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    print_str(b"[video-caller-grant] reject=");
    print_str(match reason {
        CallerMemoryRejection::MissingGrantPhysical => b"missing-physical",
        CallerMemoryRejection::MissingGrantLength => b"missing-length",
        CallerMemoryRejection::MissingCallerVa => b"missing-caller-va",
        CallerMemoryRejection::MemoryRangeNotGranted => b"memory-range-not-granted",
        CallerMemoryRejection::OutsideVideoGrant => b"outside-video-grant",
        CallerMemoryRejection::ArithmeticOverflow => b"arithmetic-overflow",
    });
    for (name, value) in [
        (&b" captured-phys="[..], grant.physical),
        (&b" captured-len="[..], grant.length),
        (&b" captured-va="[..], grant.caller_va),
        (&b" request-phys="[..], request.physical),
        (&b" request-len="[..], request.length),
    ] {
        print_str(name);
        print_hex64(value);
    }
    // These are bounded diagnostic samples, not a coherent resource authority snapshot.
    for (name, offset) in [
        (&b" pdo="[..], SH_RESOURCE_PDO_OBJECT),
        (&b" driver="[..], SH_DRVOBJ),
        (&b" current-phys="[..], SH_VIDEO_MEMORY_PHYS),
        (&b" current-len="[..], SH_VIDEO_MEMORY_LEN),
        (&b" current-va="[..], SH_VIDEO_MEMORY_CALLER_VA),
        (&b" count="[..], SH_RESOURCE_ADDRESS_COUNT),
        (&b" capacity="[..], SH_RESOURCE_ADDRESS_CAPACITY),
    ] {
        print_str(name);
        print_hex64(read_volatile((FSD_SHARED_VADDR + offset) as *const u64));
    }
    print_str(b"\n");
    let Some(count) = shared_address_resource_count(FSD_SHARED_VADDR) else {
        return;
    };
    for index in 0..count {
        let Some(resource) = read_shared_address_resource(FSD_SHARED_VADDR, index) else {
            print_str(b"[video-caller-grant] invalid-record index=");
            print_u64(index);
            print_str(b"\n");
            return;
        };
        print_str(b"[video-caller-grant] record index=");
        print_u64(index);
        for (name, value) in [
            (&b" kind="[..], resource.kind as u64),
            (&b" resource="[..], resource.resource_index as u64),
            (&b" share="[..], resource.share as u64),
            (&b" physical="[..], resource.translated_start),
            (&b" length="[..], resource.len),
            (&b" map-length="[..], resource.map_len),
        ] {
            print_str(name);
            print_hex64(value);
        }
        print_str(b"\n");
    }
}
