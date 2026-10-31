//! The installed LiberNT service wave must leave room for later shell and heap caps.

use std::fs;
use std::path::Path;

fn integer(expr: &syn::Expr) -> Option<u64> {
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(value),
        ..
    }) = expr
    else {
        return None;
    };
    value.base10_parse().ok()
}

fn constant(items: &[syn::Item], name: &str) -> u64 {
    items
        .iter()
        .find_map(|item| {
            let syn::Item::Const(item) = item else {
                return None;
            };
            if item.ident != name {
                return None;
            }
            integer(&item.expr).or_else(|| {
                let syn::Expr::Binary(binary) = &*item.expr else {
                    return None;
                };
                matches!(binary.op, syn::BinOp::Shl(_))
                    .then(|| integer(&binary.left)?.checked_shl(integer(&binary.right)? as u32))
                    .flatten()
            })
        })
        .expect("native capacity constant")
}

#[test]
fn boot_reserved_root_cnode_covers_measured_libernt_cap_working_set() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rootserver = fs::read_to_string(root.join("rust-micro/src/rootserver.rs"))
        .expect("checked-out rust-micro rootserver source");
    let boot = fs::read_to_string(root.join("rust-micro/src/boot.rs"))
        .expect("checked-out rust-micro boot source");
    let executive = fs::read_to_string(root.join("components/ntos-executive/src/main.rs"))
        .expect("executive root-slot tracker source");
    let kernel = syn::parse_file(&rootserver).expect("rootserver parses");
    let executive = syn::parse_file(&executive).expect("executive parses");
    let radix = constant(&kernel.items, "ROOTSERVER_CNODE_RADIX");
    let root_slots = 1u64 << radix;
    let tracked_slots = constant(&executive.items, "ROOT_SLOT_TRACK_CAP");

    // Native census at the last healthy Winlogon checkpoint: 259,853 allocated slots.
    // Retain one recycle-stack capacity plus one 512-frame executive heap growth beyond it.
    assert!(
        root_slots >= 259_853 + 32_768 + 512,
        "root CSpace must admit the observed live caps and a bounded shell-start runway"
    );
    assert!(
        tracked_slots >= root_slots,
        "executive live/pinned/retype bookkeeping must cover every root slot"
    );
    assert!(
        boot.contains("crate::rootserver::ROOTSERVER_CNODE_BYTES")
            && boot.contains("crate::rootserver::ROOTSERVER_CNODE_SIZE_BITS"),
        "boot must reserve aligned physical backing from the same CNode geometry"
    );
    assert!(
        rootserver.contains("initThreadCNodeSizeBits: ROOTSERVER_CNODE_RADIX as Word")
            && rootserver.contains("let cnode_slots: Word = 1u64 << ROOTSERVER_CNODE_RADIX"),
        "BootInfo must publish the same root-CNode geometry to the executive"
    );
}
