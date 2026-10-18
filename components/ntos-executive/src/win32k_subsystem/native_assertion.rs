//! Terminal, bounded diagnostics for win32k's native `RtlAssert` import.

use super::*;

const ASSERT_LABEL: u64 = 0x5741_5352; // WASR
const FIELD_BYTES: usize = 128;

unsafe fn read_image_byte(address: u64) -> Option<u8> {
    let offset = address.checked_sub(WIN32K_CODE_VA)?;
    if offset >= WIN32K_IMAGE_BYTES
        || WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) == 0
        || registered_provider_wait_domain().is_none()
    {
        return None;
    }
    let rights = *code_rights().get((offset / 0x1000) as usize)?;
    // Assertion and source-file literals reside in the provider image's read-only .rdata.
    if rights != RO_NX && rights != RW_NX && rights != 2 {
        return None;
    }
    Some(read_volatile(address as *const u8))
}

unsafe fn read_assertion_byte(address: u64) -> Option<u8> {
    if let Some(activation) = active_provider_stack_event_activation() {
        let mut byte = [0];
        if provider_input::copy_validated_input(activation, address, 1, &mut byte, ASSERT_LABEL)
            .is_ok()
        {
            return Some(byte[0]);
        }
    }
    read_image_byte(address)
}

unsafe fn read_assertion_field(pointer: u64) -> Result<([u8; FIELD_BYTES], usize), u64> {
    if pointer == 0 {
        return Err(pointer);
    }
    let mut bytes = [0; FIELD_BYTES];
    for index in 0..FIELD_BYTES {
        let address = pointer.checked_add(index as u64).ok_or(pointer)?;
        let captured = read_assertion_byte(address).ok_or(address)?;
        if captured == 0 {
            return Ok((bytes, index));
        }
        bytes[index] = captured;
    }
    Ok((bytes, FIELD_BYTES))
}

/// `VOID NTAPI RtlAssert(PVOID Assertion, PVOID File, ULONG Line, PCHAR Message)`.
pub(super) extern "win64" fn rtl_assert(
    assertion: u64,
    file: u64,
    line: u32,
    message: u64,
) -> ! {
    unsafe {
        print_str(b"[win32k-assert] request-kind=0x");
        print_hex_u64(read_volatile((WIN32K_SHARED_VADDR + SH_REQ_KIND) as *const u64));
        print_str(b" ssn=0x");
        print_hex_u64(read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SSN) as *const u64));
        print_str(b"\n");
        let assertion_bytes = read_assertion_field(assertion);
        let file_bytes = read_assertion_field(file);
        let message_bytes = (message != 0).then(|| read_assertion_field(message));
        if let (Ok((assertion_bytes, assertion_len)), Ok((file_bytes, file_len))) =
            (&assertion_bytes, &file_bytes)
        {
            let message_slice = message_bytes.as_ref().and_then(|field| match field {
                Ok((bytes, len)) => Some(&bytes[..*len]),
                Err(_) => None,
            });
            let record = nt_compat_exports::kernel_assertion::capture_bounded(
                &assertion_bytes[..*assertion_len],
                &file_bytes[..*file_len],
                line,
                message_slice,
            );
            print_record(&record);
        }
        if let Err(address) = assertion_bytes {
            print_str(b"[win32k-assert] invalid assertion pointer at 0x");
            print_hex_u64(address);
            print_str(b"\n");
        }
        if let Err(address) = file_bytes {
            print_str(b"[win32k-assert] invalid file pointer at 0x");
            print_hex_u64(address);
            print_str(b"\n");
        }
        if let Some(Err(address)) = message_bytes {
            print_str(b"[win32k-assert] invalid message pointer at 0x");
            print_hex_u64(address);
            print_str(b"\n");
        }
        crate::provider_bugcheck::report(0xc4, [ASSERT_LABEL, assertion, file, u64::from(line)])
    }
}

fn print_record(record: &nt_compat_exports::kernel_assertion::AssertionRecord) {
    print_str(b"[win32k-assert] assertion: ");
    print_str(record.assertion());
    print_str(b" file: ");
    print_str(record.file());
    print_str(b" line: ");
    print_u64(u64::from(record.line()));
    if let Some(message) = record.message() {
        print_str(b" message: ");
        print_str(message);
    }
    print_str(b"\n");
}
