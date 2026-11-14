//! Every callback the pinned LiberNT win32k can raise has a delivery contract.
//!
//! `win32ss/include/u32cb.h` (commit 8e478a22) defines 21 indices. For each, the input is the
//! argument structure its kernel caller passes to `KeUserModeCallback` and the result is what
//! the user32 handler hands to `ZwCallbackReturn`. Sizes are the AMD64 `sizeof` of the
//! structures in `win32ss/include/callback.h`; the fixed ones match the length immediates in
//! the released win32k.sys.

use nt_user_callback::{UserCallbackContract, NO_PAYLOAD_REFERENCE, USER32_CALLBACK_COUNT};

const STATUS_UNSUCCESSFUL: i32 = 0xc000_0001u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;

/// (index, name, an input length the kernel sends, the handler's successful result length).
const PINNED: &[(u32, &str, u32, u32)] = &[
    (0, "WINDOWPROC", 0x40, 0x40),
    (1, "SENDASYNCPROC", 0x28, 0),
    (2, "LOADSYSMENUTEMPLATE", 0, 8),
    (3, "LOADDEFAULTCURSORS", 4, 8),
    (4, "HOOKPROC", 0x448, 0x448),
    (5, "EVENTPROC", 0x40, 0),
    (6, "LOADMENU", 0x18 + 2, 8),
    (7, "CLIENTTHREADSTARTUP", 0, 0),
    (8, "CLIENTLOADLIBRARY", 0x28, 8),
    (9, "GETCHARSETINFO", 36, 36),
    (10, "COPYIMAGE", 0x18, 8),
    (11, "SETWNDICONS", 0x38, 0x38),
    (12, "DELIVERUSERAPC", 0, 0),
    (13, "DDEPOST", 0x50, 0x50),
    (14, "DDEGET", 0x50, 0x50),
    (15, "SETOBM", 0x5d0, 0x5d0),
    (16, "LPK", 0x48, 4),
    (18, "IMMPROCESSKEY", 0x28, 4),
    (19, "IMMLOADLAYOUT", 8, 360),
    (20, "MONITORENUMPROC", 0x30, 4),
];

#[test]
fn every_pinned_callback_is_admitted_and_its_result_accepted() {
    assert_eq!(USER32_CALLBACK_COUNT, 21);
    for &(index, name, input, result) in PINNED {
        let contract = UserCallbackContract::for_api(index)
            .unwrap_or_else(|| panic!("USER32_CALLBACK_{name} ({index}) has no contract"));
        let capacity = contract
            .minimum_result_capacity(input)
            .unwrap_or_else(|| panic!("{name}: input length 0x{input:x} refused"));
        assert!(capacity >= result, "{name}: capacity 0x{capacity:x}");
        assert!(contract.accepts_request(input, capacity.max(8), NO_PAYLOAD_REFERENCE), "{name}");
        assert!(contract.accepts_result(input, result, 0), "{name}: result 0x{result:x}");
        assert!(!contract.accepts_result(input, result + 1, 0), "{name}: oversized result");
    }
}

/// `co_UserCBClientPrinterThunk` sizes its result from the caller's `OutSize`, which the
/// bridge does not carry, and the pinned gdi32 `GdiPrinterThunk` is a stub. It stays refused.
#[test]
fn the_printer_thunk_and_indices_past_the_table_are_refused() {
    assert_eq!(UserCallbackContract::for_api(17), None);
    assert_eq!(UserCallbackContract::for_api(USER32_CALLBACK_COUNT), None);
}

#[test]
fn copy_image_carries_its_five_arguments_and_returns_one_handle() {
    let contract = UserCallbackContract::for_api(10).unwrap();
    assert_eq!(contract.minimum_result_capacity(0x18), Some(8));
    assert_eq!(contract.minimum_result_capacity(0x17), None);
    assert!(!contract.accepts_request(0x18, 8, 0));
    assert!(contract.accepts_result(0x18, 0, STATUS_UNSUCCESSFUL));
    assert!(!contract.accepts_result(0x18, 8, STATUS_UNSUCCESSFUL));
}

/// `co_IntCallLoadMenu` appends the menu name and a terminator to the 0x18-byte header;
/// `co_IntClientLoadLibrary` appends up to two terminated strings to its 0x28-byte header.
#[test]
fn string_carrying_callbacks_take_any_length_from_their_header_up() {
    let load_menu = UserCallbackContract::for_api(6).unwrap();
    assert_eq!(load_menu.minimum_result_capacity(0x18 + 2 + 2 * 9), Some(8));
    assert_eq!(load_menu.minimum_result_capacity(0x18 + 1), None);
    let load_library = UserCallbackContract::for_api(8).unwrap();
    assert_eq!(load_library.minimum_result_capacity(0x28 + 2 * 11 + 2), Some(8));
    assert_eq!(load_library.minimum_result_capacity(0x27), None);
}

/// The hook and DDE handlers return their argument block. `User32CallHookProcFromKernel`
/// also returns it with STATUS_UNSUCCESSFUL after a faulting hook, and nothing with
/// STATUS_NOT_SUPPORTED for a hook it does not know (`hook.c:677`, `:826`, `:831`).
#[test]
fn echoing_callbacks_return_their_whole_argument_block() {
    for index in [4, 13, 14] {
        let contract = UserCallbackContract::for_api(index).unwrap();
        let input = 0x478;
        assert_eq!(contract.minimum_result_capacity(input), Some(input));
        assert!(contract.accepts_result(input, input, 0));
        assert!(!contract.accepts_result(input, 0, 0));
        assert!(!contract.accepts_result(input, input - 8, 0));
        assert!(contract.accepts_result(input, input, STATUS_UNSUCCESSFUL));
        assert!(contract.accepts_result(input, 0, STATUS_NOT_SUPPORTED));
        assert!(!contract.accepts_result(input, 8, STATUS_UNSUCCESSFUL));
    }
    assert_eq!(UserCallbackContract::for_api(4).unwrap().minimum_result_capacity(0x447), None);
    assert_eq!(UserCallbackContract::for_api(13).unwrap().minimum_result_capacity(0x4f), None);
}

#[test]
fn only_the_window_procedure_binds_a_window_to_the_client_thread() {
    for &(index, name, _, _) in PINNED {
        let binds = UserCallbackContract::for_api(index).unwrap().requires_window_binding();
        assert_eq!(binds, index == 0, "{name}");
    }
}
