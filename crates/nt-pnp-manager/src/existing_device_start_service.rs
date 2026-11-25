/// A missing Service value has different meaning from a missing Enum key or broken configured
/// service. Only the former can admit an already published raw PDO to direct START.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingDeviceStartServiceError {
    MissingService,
    Failure(i32),
}

/// Resolve the Service value by an already opened exact Enum key ID. Once the value exists,
/// every failure in decoding or launching its configured service remains a service failure.
pub fn resolve_existing_device_start_service<T, U>(
    enum_key: Result<u64, i32>,
    read_service: impl FnOnce(u64) -> Result<T, i32>,
    configured_launch: impl FnOnce(T) -> Result<U, i32>,
) -> Result<U, ExistingDeviceStartServiceError> {
    let key = enum_key.map_err(ExistingDeviceStartServiceError::Failure)?;
    let service = read_service(key).map_err(|status| {
        if status == nt_status::NtStatus::OBJECT_NAME_NOT_FOUND.raw() {
            ExistingDeviceStartServiceError::MissingService
        } else {
            ExistingDeviceStartServiceError::Failure(status)
        }
    })?;
    configured_launch(service).map_err(ExistingDeviceStartServiceError::Failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;

    #[test]
    fn only_missing_service_value_on_existing_enum_key_admits_raw_candidate() {
        let absent = resolve_existing_device_start_service(
            Ok(19),
            |key| { assert_eq!(key, 19); Err::<&str, _>(NAME_NOT_FOUND) },
            |_| Ok::<_, i32>(()),
        );
        assert_eq!(absent, Err(ExistingDeviceStartServiceError::MissingService));

        let missing_key = resolve_existing_device_start_service(
            Err(NAME_NOT_FOUND),
            |_| Ok::<_, i32>("FixedButton"),
            |_| Ok::<_, i32>(()),
        );
        assert_eq!(missing_key, Err(ExistingDeviceStartServiceError::Failure(NAME_NOT_FOUND)));

        let configured_but_broken = resolve_existing_device_start_service(
            Ok(19),
            |_| Ok::<_, i32>("ConfiguredService"),
            |_| Err::<(), _>(NAME_NOT_FOUND),
        );
        assert_eq!(configured_but_broken,
            Err(ExistingDeviceStartServiceError::Failure(NAME_NOT_FOUND)));
    }

    #[test]
    fn configured_service_keeps_its_named_launch_and_other_query_errors_do_not_become_raw() {
        let configured = resolve_existing_device_start_service(
            Ok(23),
            |key| {
                assert_eq!(key, 23);
                Ok::<_, i32>("DiskClass")
            },
            |service| {
                assert_eq!(service, "DiskClass");
                Ok::<_, i32>("named function stack")
            },
        );
        assert_eq!(configured, Ok("named function stack"));

        let access_denied = 0xC000_0022u32 as i32;
        let refused = resolve_existing_device_start_service(
            Ok(23),
            |_| Err::<&str, _>(access_denied),
            |_| Ok::<_, i32>("unreachable"),
        );
        assert_eq!(refused, Err(ExistingDeviceStartServiceError::Failure(access_denied)));
    }
}
