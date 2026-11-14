//! A win32k service the executive stages must carry the argument count the pinned release
//! registers for it. The count is a property of the release, not of a call's values.

use std::fs;
use std::path::PathBuf;

use nt_compat_exports::ssdt::x64_argument_count_from_sspt_byte;
use nt_kernel_exec::user_window_list::{BUILD_HWND_LIST_ARGUMENTS, BUILD_HWND_LIST_SSN};

const SOURCE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";
const WIN32K_SERVICE_BASE: u64 = 0x1000;

/// `win32ss/w32ksvc64.h` opens with UserGetThreadState(1), UserPeekMessage(5),
/// UserCallOneParam(2), UserGetKeyState(1), UserInvalidateRect(3), UserCallNoParam(1),
/// UserGetMessage(4), UserMessageCall(7); the argument table stores eight bytes per argument.
const ARGUMENT_TABLE_HEAD: [u8; 8] = [8, 40, 16, 8, 24, 8, 32, 56];

/// (service number, arguments the executive forwards, pinned `SVC_` name).
const STAGED_SERVICES: &[(u64, usize, &str)] =
    &[(BUILD_HWND_LIST_SSN, BUILD_HWND_LIST_ARGUMENTS, "UserBuildHwndList")];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn argument_table(image: &[u8]) -> &[u8] {
    let mut found = image
        .windows(ARGUMENT_TABLE_HEAD.len())
        .enumerate()
        .filter(|(_, window)| *window == ARGUMENT_TABLE_HEAD)
        .map(|(offset, _)| offset);
    let offset = found.next().expect("argument table in pinned win32k.sys");
    assert!(found.next().is_none(), "argument table head must be unique");
    &image[offset..]
}

#[test]
fn staged_services_forward_the_argument_count_the_release_registers() {
    if let Ok(manifest) = fs::read_to_string(root().join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.lines().any(|line| line == SOURCE_REVISION));
    }
    // The pinned release image may be absent on CI; the constants are then checked only
    // against each other by their own crate tests.
    let image = root().join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if !image.exists() {
        return;
    }
    let bytes = fs::read(image).expect("cached pinned LiberNT win32k.sys");
    let table = argument_table(&bytes);
    for &(ssn, forwarded, name) in STAGED_SERVICES {
        let index = usize::try_from(ssn - WIN32K_SERVICE_BASE).unwrap();
        assert_eq!(
            x64_argument_count_from_sspt_byte(table[index]) as usize,
            forwarded,
            "{name} (0x{ssn:x})"
        );
    }
}
