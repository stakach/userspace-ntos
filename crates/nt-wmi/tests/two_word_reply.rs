use nt_wmi::reply::TwoWordReply;

#[test]
fn ignores_registers_outside_the_declared_reply() {
    let reply = TwoWordReply::decode(2, [0, 17, 0xfeed, 0xbeef]).unwrap();
    assert_eq!(reply.status, 0);
    assert_eq!(reply.value, 17);
}

#[test]
fn rejects_a_reply_without_exactly_two_words() {
    assert!(TwoWordReply::decode(1, [0, 17, 0, 0]).is_none());
    assert!(TwoWordReply::decode(3, [0, 17, 0, 0]).is_none());
}
