#[path = "../../../components/ntos-executive/src/ring_channel_completion.rs"]
mod ring_channel_completion;

use ring_channel_completion::CompletionInbox;

#[derive(Debug, Eq, PartialEq)]
struct Reply {
    status: u32,
    payload: [u8; 4],
}

#[test]
fn nested_wait_preserves_outer_completion_and_its_payload() {
    let mut inbox = CompletionInbox::new();
    let outer = 41;
    let nested = 42;

    // The outer CQE can arrive while the nested wait is consuming the same completion ring.
    assert_eq!(
        inbox.accept(
            nested,
            outer,
            Reply {
                status: 0,
                payload: *b"OUTR",
            },
        ),
        None
    );
    assert_eq!(
        inbox.accept(
            nested,
            nested,
            Reply {
                status: 0,
                payload: *b"NEST",
            },
        ),
        Some(Reply {
            status: 0,
            payload: *b"NEST",
        })
    );

    assert_eq!(
        inbox.take(outer),
        Some(Reply {
            status: 0,
            payload: *b"OUTR",
        }),
        "outer completion and payload must remain available to the outer request"
    );
}

#[test]
fn shared_request_frame_rejects_nested_submission_until_owner_finishes() {
    let mut inbox = CompletionInbox::<Reply>::new();
    assert!(inbox.begin(41));
    assert!(!inbox.begin(42), "nested request must not overwrite the outer request frame");
    inbox.finish(41);
    assert!(inbox.begin(42));
    inbox.finish(42);
}
