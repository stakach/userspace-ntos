use nt_compat_exports::crt::memchr;
use nt_compat_exports::crt::strchr;

#[test]
fn memchr_returns_first_match_within_exact_bound() {
    assert_eq!(memchr(b"ababa", b'a', 5), Some(0));
    assert_eq!(memchr(b"ababa", b'a', 0), None);
    assert_eq!(memchr(b"ababa", b'a', 3), Some(0));
    assert_eq!(memchr(b"ababa", b'b', 1), None);
    assert_eq!(memchr(b"ababa", b'b', 2), Some(1));
}

#[test]
fn strchr_finds_first_match_and_the_terminal_nul() {
    assert_eq!(strchr(b"abca\0", b'a'), Some(0));
    assert_eq!(strchr(b"abca\0", b'c'), Some(2));
    assert_eq!(strchr(b"abca\0", b'\0'), Some(4));
    assert_eq!(strchr(b"abca\0", b'z'), None);
}
