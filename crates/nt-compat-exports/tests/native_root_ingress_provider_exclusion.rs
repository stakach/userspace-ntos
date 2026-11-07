//! A retained ordinary root child must keep provider selection behind its exact physical parent.

const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const NESTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");
const RESUME: &str = include_str!("../../../components/ntos-executive/src/component_resume.rs");
const EXECUTE: &str = include_str!("../../../components/ntos-executive/src/component_resume_execute.rs");

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
fn held_root_child_blocks_outer_and_tail_provider_selection() {
    let child = function(HOSTED, "root_ingress_parent_blocks_provider_resume");
    assert!(child.contains("root.pass.admission_key()")
        && child.contains("root.pass.child()")
        && child.contains("nested::root_ingress_parent_is_held")
        && child.contains("root_child_admission_current(row, root.pass.admission_key())"),
        "provider exclusion must be derived from the retained exact child and parent");

    let admission = function(HOSTED, "root_child_admission_current");
    assert!(admission.contains("call.admission_key() == admission")
        && admission.contains("row.completion.is_some()")
        && admission.contains("ready.reply() == admission.reply()"),
        "one authority must match both live and settled retained child Calls");

    let parent = function(NESTED, "root_ingress_parent_is_held");
    assert!(parent.contains("row_matches(handle, parent)")
        && parent.contains("parent.root_admission == Some(admission)")
        && parent.contains("parent.child == Some(ParentChild::RootIngress)")
        && parent.contains("parent.physical.held()"),
        "provider exclusion must authenticate the physical parent and its sealed scope identity");

    let outer = function(RESUME, "run_outer");
    let outer_guard = outer.find("root_ingress_parent_blocks_provider_resume()").unwrap();
    assert!(outer_guard < outer.find("drain_shared_returns()").unwrap()
        && outer_guard < outer.find("next_ready_ticket()").unwrap(),
        "outer provider and maintenance work must wait for the root child's checkpoint");

    let tail = function(RESUME, "drain_hosted_ready");
    let tail_guard = tail.find("root_ingress_parent_blocks_provider_resume()").unwrap();
    assert!(tail_guard < tail.find("select_ready_service_waits()").unwrap()
        && tail_guard < tail.find("next_in_pass(").unwrap(),
        "late provider selection must wait for exact parent restoration");

    let provider = function(EXECUTE, "run_hosted");
    assert!(provider.find("root_ingress_parent_blocks_provider_resume()").unwrap()
        < provider.find("begin_resume(").unwrap(),
        "direct provider entry must recheck the held-parent exclusion");

    let restored = function(HOSTED, "accept_root_ingress_parent_restored");
    assert!(restored.contains("root.restored = Some(restored)")
        && restored.contains("root.parent = None")
        && restored.contains("root_child_admission_current(row, restored.admission_key())"),
        "only a positive exact parent restore receipt may end provider exclusion");
    assert!(child.contains("root.restored.as_ref()")
        && child.contains("restored.admission_key() != root.pass.admission_key()")
        && child.contains("false\n}"),
        "late async child completion must not retain a stale parent exclusion");
}
