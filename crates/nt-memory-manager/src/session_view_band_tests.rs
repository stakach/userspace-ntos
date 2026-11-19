use super::*;

const BASE: u64 = 0x0000_0100_4a00_0000;
const MIB: u64 = 1 << 20;

fn band() -> SessionViewBand {
    SessionViewBand::new(BASE, 96 * MIB)
}

/// Commit every uncommitted page of `range` with synthetic frame and provider caps.
fn commit(band: &mut SessionViewBand, address: u64, bytes: u64) -> Result<CommitRange, BandError> {
    let range = band.commit_range(address, bytes)?;
    while let Some(page) = band.next_uncommitted(range)? {
        band.begin_commit(range.reservation, page)?;
        band.complete_commit(range.reservation, page, 0x1000 + page / PAGE_SIZE, 0x2000 + page / PAGE_SIZE)?;
    }
    Ok(range)
}

#[test]
fn a_twenty_mib_reservation_consumes_virtual_addresses_only() {
    // Boot 44492044547: UserCreateHeap reserves gdwDesktopSectionSize * 1024 = 20 MiB for
    // "Default". The view must reserve all of it without backing any page.
    let mut band = band();
    let default = band.reserve(20 * MIB).unwrap();
    let disconnect = band.reserve(20 * MIB).unwrap();
    let winlogon = band.reserve(128 * 1024).unwrap();
    assert_eq!(default.bytes, 20 * MIB);
    assert_eq!(band.reserved_bytes(), 40 * MIB + 128 * 1024);
    assert_eq!(band.committed_pages(), 0);
    for view in [default, disconnect, winlogon] {
        assert_eq!(view.base % VIEW_ALIGNMENT, 0);
        assert_eq!(band.access(view.base), PageAccess::Uncommitted);
        assert_eq!(band.access(view.end() - 1), PageAccess::Uncommitted);
    }
    assert!(default.end() <= disconnect.base && disconnect.end() <= winlogon.base);
}

#[test]
fn commit_backs_only_the_committed_pages() {
    let mut band = band();
    let view = band.reserve(20 * MIB).unwrap();
    // IntUserHeapCreate commits the first page before RtlCreateHeap.
    commit(&mut band, view.base, PAGE_SIZE).unwrap();
    assert_eq!(band.committed_pages(), 1);
    assert_eq!(band.access(view.base), PageAccess::Committed);
    assert_eq!(band.access(view.base + PAGE_SIZE), PageAccess::Uncommitted);
    let page = band.committed(view.base).unwrap();
    assert_eq!((page.address, page.clients), (view.base, 0));
    // Heap growth commits more; committing an already committed page charges nothing again.
    commit(&mut band, view.base, 3 * PAGE_SIZE).unwrap();
    assert_eq!(band.committed_pages(), 3);
    assert_eq!(band.committed(view.base), Some(page));
}

#[test]
fn commit_rounds_to_whole_pages_like_mem_commit() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    let range = band.commit_range(view.base + 0x1ff0, 0x20).unwrap();
    assert_eq!((range.base, range.bytes), (view.base + 0x1000, 0x2000));
    let range = band.commit_range(view.base + 0x10, 1).unwrap();
    assert_eq!((range.base, range.bytes), (view.base, PAGE_SIZE));
    assert_eq!(band.commit_range(view.base, 0), Err(BandError::InvalidSize));
}

#[test]
fn reservations_are_page_rounded_and_view_aligned() {
    let mut band = band();
    let first = band.reserve(0x1234).unwrap();
    assert_eq!(first.bytes, 0x2000);
    let second = band.reserve(PAGE_SIZE).unwrap();
    assert_eq!(second.base, first.base + VIEW_ALIGNMENT);
    assert_eq!(band.reserve(0), Err(BandError::InvalidSize));
}

#[test]
fn commit_outside_one_view_is_refused() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    // The range starts in the view but runs past its end: the VAD check fails.
    assert_eq!(
        band.commit_range(view.end() - PAGE_SIZE, 2 * PAGE_SIZE).map_err(BandError::status),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    // An unreserved address in the band is not a view at all.
    assert_eq!(band.commit_range(view.end() + VIEW_ALIGNMENT, PAGE_SIZE), Err(BandError::NotReserved));
    assert_eq!(band.committed_pages(), 0);
}

#[test]
fn an_uncommitted_reserved_page_is_never_backed_on_access() {
    let mut band = band();
    let view = band.reserve(20 * MIB).unwrap();
    commit(&mut band, view.base, PAGE_SIZE).unwrap();
    // A touch beyond the committed prefix observes no backing; the fault policy refuses it.
    assert_eq!(band.access(view.base + PAGE_SIZE), PageAccess::Uncommitted);
    assert_eq!(band.committed(view.base + PAGE_SIZE), None);
    assert_eq!(band.access(BASE + 95 * MIB), PageAccess::Unreserved);
    assert_eq!(band.committed_pages(), 1);
}

#[test]
fn section_pages_cannot_be_decommitted_through_a_view() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    commit(&mut band, view.base, PAGE_SIZE).unwrap();
    assert_eq!(
        band.decommit(view.base, PAGE_SIZE).map_err(BandError::status),
        Err(STATUS_UNABLE_TO_DELETE_SECTION)
    );
    assert_eq!(band.committed_pages(), 1);
}

#[test]
fn release_retires_every_committed_page_then_frees_the_view() {
    let mut band = band();
    let view = band.reserve(20 * MIB).unwrap();
    commit(&mut band, view.base, 4 * PAGE_SIZE).unwrap();
    commit(&mut band, view.base + 10 * MIB, PAGE_SIZE).unwrap();
    assert_eq!(band.committed_pages(), 5);
    band.begin_release(view).unwrap();
    // A deleted Section accepts no further commit.
    assert_eq!(band.commit_range(view.base, PAGE_SIZE), Err(BandError::Releasing));
    assert_eq!(band.complete_release(view), Err(BandError::PagesRemain));
    let mut frames = Vec::new();
    while let Some(page) = band.next_retirement(view).unwrap() {
        frames.push(page.frame);
        band.complete_page_retirement(view, page.address).unwrap();
    }
    assert_eq!(frames.len(), 5);
    assert_eq!(band.committed_pages(), 0);
    band.complete_release(view).unwrap();
    assert_eq!(band.reserved_bytes(), 0);
    assert_eq!(band.reservation_at(view.base), None);
    // The addresses are reusable, under a new generation.
    let again = band.reserve(20 * MIB).unwrap();
    assert_eq!(again.base, view.base);
    assert_ne!(again.generation, view.generation);
    assert_eq!(band.access(again.base), PageAccess::Uncommitted);
}

#[test]
fn a_stale_reservation_cannot_commit_into_its_successor() {
    let mut band = band();
    let old = band.reserve(64 * 1024).unwrap();
    band.begin_release(old).unwrap();
    band.complete_release(old).unwrap();
    let new = band.reserve(64 * 1024).unwrap();
    assert_eq!(new.base, old.base);
    assert_eq!(band.begin_commit(old, old.base), Err(BandError::StaleReservation));
    assert_eq!(band.begin_release(old), Err(BandError::StaleReservation));
}

#[test]
fn an_uncertain_effect_quarantines_the_page_and_its_view() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    let range = band.commit_range(view.base, PAGE_SIZE).unwrap();
    band.begin_commit(view, view.base).unwrap();
    band.quarantine(view.base);
    assert_eq!(band.access(view.base), PageAccess::Unavailable);
    assert_eq!(band.next_uncommitted(range), Err(BandError::Quarantined));
    band.begin_release(view).unwrap();
    assert_eq!(band.next_retirement(view), Ok(None));
    assert_eq!(band.complete_release(view), Err(BandError::Quarantined));
    assert_eq!(band.reservation_at(view.base), Some(view));
}

#[test]
fn accounting_counts_committed_frames_not_reservations() {
    let mut band = band();
    let default = band.reserve(20 * MIB).unwrap();
    let disconnect = band.reserve(20 * MIB).unwrap();
    commit(&mut band, default.base, 16 * PAGE_SIZE).unwrap();
    commit(&mut band, disconnect.base, PAGE_SIZE).unwrap();
    assert_eq!(band.committed_pages(), 17);
    assert_eq!(band.reserved_bytes(), 40 * MIB);
}

#[test]
fn the_band_refuses_reservations_beyond_its_window() {
    let mut band = band();
    let mut views = Vec::new();
    while let Ok(view) = band.reserve(20 * MIB) {
        views.push(view);
    }
    assert_eq!(views.len(), 4);
    assert_eq!(band.reserve(20 * MIB).map_err(BandError::status), Err(STATUS_NO_MEMORY));
    // The remaining space still serves a small non-interactive desktop heap.
    assert!(band.reserve(128 * 1024).is_ok());
}

#[test]
fn commits_reach_every_admitted_client_and_late_clients_catch_up() {
    let mut band = band();
    let view = band.reserve(20 * MIB).unwrap();
    band.admit_client(3).unwrap();
    commit(&mut band, view.base, 2 * PAGE_SIZE).unwrap();
    assert_eq!(band.clients_missing(view.base), 1 << 3);
    band.record_client_mapping(view.base, 3).unwrap();
    band.record_client_mapping(view.base + PAGE_SIZE, 3).unwrap();
    assert_eq!(band.clients_missing(view.base), 0);
    assert_eq!(band.next_unmapped_for_client(3, 0), None);

    // A client connecting later sees every page committed before it, in address order.
    band.admit_client(5).unwrap();
    let first = band.next_unmapped_for_client(5, 0).unwrap();
    assert_eq!(first.address, view.base);
    band.record_client_mapping(first.address, 5).unwrap();
    assert_eq!(band.next_unmapped_for_client(5, 0).unwrap().address, view.base + PAGE_SIZE);
    // An unadmitted client is never handed pages.
    assert_eq!(band.next_unmapped_for_client(6, 0), None);
    assert_eq!(band.record_client_mapping(view.base, 6), Err(BandError::InvalidClient));
}

#[test]
fn a_page_retires_only_after_its_client_aliases_are_removed() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    band.admit_client(2).unwrap();
    commit(&mut band, view.base, PAGE_SIZE).unwrap();
    band.record_client_mapping(view.base, 2).unwrap();
    band.begin_release(view).unwrap();
    let page = band.next_retirement(view).unwrap().unwrap();
    assert_eq!(page.clients, 1 << 2);
    assert_eq!(band.complete_page_retirement(view, page.address), Err(BandError::PagesRemain));
    // The same page is offered again until its aliases are gone.
    assert_eq!(band.next_retirement(view).unwrap(), Some(page));
    band.clear_client_mapping(page.address, 2).unwrap();
    band.complete_page_retirement(view, page.address).unwrap();
    band.complete_release(view).unwrap();
}

#[test]
fn a_departed_client_holds_no_page() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    band.admit_client(4).unwrap();
    commit(&mut band, view.base, PAGE_SIZE).unwrap();
    band.record_client_mapping(view.base, 4).unwrap();
    band.forget_client(4);
    assert_eq!(band.clients(), 0);
    assert_eq!(band.committed(view.base).unwrap().clients, 0);
    commit(&mut band, view.base + PAGE_SIZE, PAGE_SIZE).unwrap();
    assert_eq!(band.clients_missing(view.base + PAGE_SIZE), 0);
}

#[test]
fn a_commit_without_backing_leaves_the_page_reserved() {
    let mut band = band();
    let view = band.reserve(64 * 1024).unwrap();
    band.begin_commit(view, view.base).unwrap();
    assert_eq!(band.access(view.base), PageAccess::Unavailable);
    band.abort_commit(view, view.base).unwrap();
    assert_eq!(band.access(view.base), PageAccess::Uncommitted);
    assert_eq!(band.committed_pages(), 0);
    assert_eq!(band.abort_commit(view, view.base), Err(BandError::EffectInProgress));
    commit(&mut band, view.base, PAGE_SIZE).unwrap();
    assert_eq!(band.committed_pages(), 1);
}
