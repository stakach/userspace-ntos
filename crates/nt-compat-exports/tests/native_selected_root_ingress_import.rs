//! Selected root ingress imports only its retained Call and complete receive bank.

const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const ORDINARY: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("missing {name}"));
    let tail = &source[start..];
    let open = tail.find('{').unwrap();
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes().iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 { return &tail[..=offset]; }
            }
            _ => {}
        }
    }
    panic!("unclosed {name}")
}

#[test]
fn exact_selected_child_retains_full_message_and_seals_before_import_effect() {
    let selected = function(HOSTED, "take_selected_root_hosted_with");
    assert!(selected.contains("row.binding == snapshot.binding")
        && selected.contains("call.admission_key() != admission")
        && selected.contains("parent.identity() != parent_identity")
        && selected.contains("root_ingress_parent_is_held")
        && selected.contains("ReplyBindingObservation::BoundToTarget"),
        "selection requires the exact child, parent and physical Reply binding");
    assert!(selected.contains("call.message().clone()")
        && !selected.contains("ReceivedMessage::new("),
        "import must return the retained complete message, including its IPC tail bank");
    let begin = selected.find("root.pass.begin_import").unwrap();
    let effect = selected.find("import(reply, &message)").unwrap();
    let positive = selected.find("root.pass.deliver").unwrap();
    let delivered = selected.find("row.delivered = true").unwrap();
    assert!(begin < effect && effect < positive && positive < delivered,
        "the one-shot pass seals before physical import and delivers only after success");
    assert!(selected.contains("return Err(Error::Retain)")
        && !selected.contains("root.pass.begin_import(binding, call).ok()"),
        "an uncertain callback cannot reopen import or synthesize delivery");
    let generic = function(ORDINARY, "receive");
    assert!(!generic.contains("take_selected_root_hosted_with"),
        "the selected adapter remains dormant until the outer handoff is reviewed");
}
