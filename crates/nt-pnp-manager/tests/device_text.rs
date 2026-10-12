use nt_pnp_manager::device_text::{
    plan_device_text_publication, DeviceTextPublication, DeviceTextPublicationError,
    DeviceTextRegistryValue, NoDeviceText, DEVICE_TEXT_LOCATION_INFORMATION, REG_SZ,
};
use nt_pnp_manager::returned_pnp_buffer::{
    ReleaseResult, ReturnedPnpBufferCatalog, ReturnedPnpQuery, ReturnedPnpRequest,
};

#[path = "returned_pnp_buffer/fixture.rs"]
mod fixture;
use fixture::{allocation, other_request, request, NOT_SUPPORTED, SUCCESS};

fn published(
    request: ReturnedPnpRequest,
) -> (
    ReturnedPnpBufferCatalog,
    nt_pnp_manager::returned_pnp_buffer::ReturnedPnpBufferTicket,
) {
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let ticket = catalog.prepare(request).unwrap();
    let returned = allocation();
    catalog
        .publish_terminal(
            ticket,
            request,
            SUCCESS,
            returned.pool.component_address,
            Some(returned),
        )
        .unwrap();
    (catalog, ticket)
}

#[test]
fn provider_unicode_description_includes_one_terminator_before_arrival_write() {
    let request = request();
    let (catalog, ticket) = published(request);
    let source = "PCI — 猫😀";
    let mut bytes = Vec::new();
    for unit in source.encode_utf16().chain([0, 0x7777]) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let expected_len = (source.encode_utf16().count() + 1) * 2;
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(allocation()),
            Some(&bytes),
            false,
        ),
        Ok(DeviceTextPublication::Write(DeviceTextRegistryValue {
            name: "DeviceDesc",
            value_type: REG_SZ,
            data: bytes[..expected_len].to_vec(),
        }))
    );
}

#[test]
fn installed_description_is_preserved_and_location_is_overwritten() {
    let request = request();
    let (catalog, ticket) = published(request);
    assert_eq!(
        plan_device_text_publication(&catalog, ticket, request, Some(allocation()), None, true,),
        Ok(DeviceTextPublication::KeepExistingDescription)
    );
    let location_request = ReturnedPnpRequest {
        query: ReturnedPnpQuery::DeviceText {
            text_type: DEVICE_TEXT_LOCATION_INFORMATION,
            locale_id: 0x409,
        },
        ..other_request()
    };
    let (catalog, ticket) = published(location_request);
    let text = [b'B', 0, b'u', 0, b's', 0, 0, 0];
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            location_request,
            Some(allocation()),
            Some(&text),
            true,
        ),
        Ok(DeviceTextPublication::Write(DeviceTextRegistryValue {
            name: "LocationInformation",
            value_type: REG_SZ,
            data: text.to_vec(),
        }))
    );
}

#[test]
fn unsupported_and_empty_are_distinct_and_never_create_a_label() {
    let request = request();
    let mut catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let ticket = catalog.prepare(request).unwrap();
    catalog
        .publish_terminal(ticket, request, NOT_SUPPORTED, 0x500000, None)
        .unwrap();
    assert_eq!(
        plan_device_text_publication(&catalog, ticket, request, None, None, false),
        Ok(DeviceTextPublication::NoText(NoDeviceText::Unsupported(
            NOT_SUPPORTED
        )))
    );
    let mut failed_catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let failed_ticket = failed_catalog.prepare(request).unwrap();
    let provider_failure = 0xc000_009a;
    failed_catalog
        .publish_terminal(failed_ticket, request, provider_failure, 0, None)
        .unwrap();
    assert_eq!(
        plan_device_text_publication(&failed_catalog, failed_ticket, request, None, None, false),
        Err(DeviceTextPublicationError::ProviderFailure(
            provider_failure
        ))
    );
    let (catalog, ticket) = published(other_request());
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            other_request(),
            Some(allocation()),
            Some(&[0, 0]),
            false,
        ),
        Ok(DeviceTextPublication::NoText(NoDeviceText::Empty))
    );
}

#[test]
fn malformed_or_out_of_allocation_text_never_yields_registry_data() {
    let request = request();
    let (catalog, ticket) = published(request);
    for bad in [&[b'A', 0][..], &[b'A'][..]] {
        assert!(plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(allocation()),
            Some(bad),
            false,
        )
        .is_err());
    }
    // ReactOS copies WCHAR units into REG_SZ without Unicode scalar validation.
    let unpaired_surrogate = [0x00, 0xd8, 0, 0];
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(allocation()),
            Some(&unpaired_surrogate),
            false,
        ),
        Ok(DeviceTextPublication::Write(DeviceTextRegistryValue {
            name: "DeviceDesc",
            value_type: REG_SZ,
            data: unpaired_surrogate.to_vec(),
        }))
    );
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(allocation()),
            Some(&[0; 66]),
            false,
        ),
        Err(DeviceTextPublicationError::OutOfBounds)
    );
}

#[test]
fn wrong_request_generation_allocation_and_phase_are_rejected() {
    let request = request();
    let (mut catalog, ticket) = published(request);
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            other_request(),
            Some(allocation()),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::WrongRequest)
    );
    let mut stale_allocation = allocation();
    stale_allocation.pool.pool_generation += 1;
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(stale_allocation),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::WrongAllocation)
    );
    let mut foreign_arena = allocation();
    foreign_arena.arena.domain.cookie += 1;
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(foreign_arena),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::WrongAllocation)
    );
    assert_eq!(
        plan_device_text_publication(&catalog, ticket, request, Some(allocation()), None, false),
        Err(DeviceTextPublicationError::MissingRead)
    );
    let release = catalog.begin_release(ticket, allocation()).unwrap();
    catalog
        .observe_release(release, ReleaseResult::Uncertain)
        .unwrap();
    assert_eq!(
        plan_device_text_publication(
            &catalog,
            ticket,
            request,
            Some(allocation()),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::WrongPhase)
    );
}

#[test]
fn prepared_or_foreign_catalog_ticket_cannot_authorize_registry_publication() {
    let request = request();
    let mut prepared_catalog = ReturnedPnpBufferCatalog::new().unwrap();
    let prepared_ticket = prepared_catalog.prepare(request).unwrap();
    assert_eq!(
        plan_device_text_publication(
            &prepared_catalog,
            prepared_ticket,
            request,
            Some(allocation()),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::WrongPhase)
    );
    let (published_catalog, published_ticket) = published(other_request());
    assert_eq!(
        plan_device_text_publication(
            &published_catalog,
            prepared_ticket,
            request,
            Some(allocation()),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::ForeignOrRetiredTicket)
    );
    assert_eq!(
        plan_device_text_publication(
            &prepared_catalog,
            published_ticket,
            other_request(),
            Some(allocation()),
            Some(&[b'A', 0, 0, 0]),
            false,
        ),
        Err(DeviceTextPublicationError::ForeignOrRetiredTicket)
    );
}

#[test]
fn query_id_and_unknown_text_type_cannot_publish_device_text() {
    for query in [
        ReturnedPnpQuery::QueryId { id_type: 0 },
        ReturnedPnpQuery::DeviceText {
            text_type: 99,
            locale_id: 0x409,
        },
    ] {
        let request = ReturnedPnpRequest { query, ..request() };
        let (catalog, ticket) = published(request);
        assert_eq!(
            plan_device_text_publication(
                &catalog,
                ticket,
                request,
                Some(allocation()),
                Some(&[b'A', 0, 0, 0]),
                false,
            ),
            Err(DeviceTextPublicationError::WrongQuery)
        );
    }
}
