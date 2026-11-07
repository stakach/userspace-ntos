use nt_user_callback::{UserCallbackContract, NO_PAYLOAD_REFERENCE};

// LiberNT's pinned win32ss/include/u32cb.h assigns API 9 to GETCHARSETINFO.
// GET_CHARSET_INFO is LCID (4 bytes) followed by CHARSETINFO (32 bytes).
#[test]
fn get_charset_info_retains_the_user32_result_even_on_lookup_failure() {
    let callback = UserCallbackContract::for_api(9).expect("GETCHARSETINFO callback contract");
    const LENGTH: u32 = 36;
    const STATUS_UNSUCCESSFUL: i32 = 0xc000_0001u32 as i32;

    assert_eq!(callback.minimum_result_capacity(LENGTH), Some(LENGTH));
    assert_eq!(callback.minimum_result_capacity(LENGTH - 1), None);
    assert!(callback.accepts_request(LENGTH, LENGTH, NO_PAYLOAD_REFERENCE));
    assert!(!callback.accepts_request(LENGTH - 1, LENGTH, NO_PAYLOAD_REFERENCE));
    assert!(!callback.accepts_request(LENGTH, LENGTH - 1, NO_PAYLOAD_REFERENCE));
    assert!(!callback.accepts_request(LENGTH, LENGTH, 0));

    // User32CallGetCharsetInfo passes the original Arguments and ArgumentLength
    // to ZwCallbackReturn for both STATUS_SUCCESS and STATUS_UNSUCCESSFUL.
    assert!(callback.accepts_result(LENGTH, LENGTH, 0));
    assert!(callback.accepts_result(LENGTH, LENGTH, STATUS_UNSUCCESSFUL));
    assert!(!callback.accepts_result(LENGTH, LENGTH - 1, 0));
    assert!(!callback.accepts_result(LENGTH, LENGTH + 1, 0));
    assert!(!callback.accepts_result(LENGTH, LENGTH - 1, STATUS_UNSUCCESSFUL));
}

// LiberNT's pinned win32ss/include/u32cb.h assigns API 19 to IMMLOADLAYOUT.
// On x64, HKL is 8 bytes; BOOL plus padding and IMEINFOEX total 360 bytes.
#[test]
fn imm_load_layout_requires_the_exact_x64_result_shape() {
    let callback = UserCallbackContract::for_api(19).expect("IMMLOADLAYOUT callback contract");
    const INPUT_LENGTH: u32 = 8;
    const RESULT_LENGTH: u32 = 360;

    assert_eq!(callback.minimum_result_capacity(INPUT_LENGTH), Some(RESULT_LENGTH));
    assert_eq!(callback.minimum_result_capacity(INPUT_LENGTH - 1), None);
    assert!(callback.accepts_request(INPUT_LENGTH, RESULT_LENGTH, NO_PAYLOAD_REFERENCE));
    assert!(!callback.accepts_request(INPUT_LENGTH - 1, RESULT_LENGTH, NO_PAYLOAD_REFERENCE));
    assert!(!callback.accepts_request(INPUT_LENGTH, RESULT_LENGTH - 1, NO_PAYLOAD_REFERENCE));
    assert!(!callback.accepts_request(INPUT_LENGTH, RESULT_LENGTH, 0));
    assert!(callback.accepts_result(INPUT_LENGTH, RESULT_LENGTH, 0));
    assert!(!callback.accepts_result(INPUT_LENGTH, RESULT_LENGTH - 1, 0));
    assert!(!callback.accepts_result(INPUT_LENGTH, RESULT_LENGTH + 1, 0));
}
