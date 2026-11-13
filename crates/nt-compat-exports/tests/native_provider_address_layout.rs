use std::collections::HashMap;
use syn::{BinOp, Expr, Item};

fn evaluate(expression: &Expr, constants: &HashMap<String, Expr>) -> u64 {
    match expression {
        Expr::Lit(value) => match &value.lit {
            syn::Lit::Int(value) => value.base10_parse().unwrap(),
            _ => panic!("address constant must be numeric"),
        },
        Expr::Path(value) => evaluate(&constants[&value.path.segments.last().unwrap().ident.to_string()], constants),
        Expr::Cast(value) => evaluate(&value.expr, constants),
        Expr::Paren(value) => evaluate(&value.expr, constants),
        Expr::Binary(value) => {
            let left = evaluate(&value.left, constants);
            let right = evaluate(&value.right, constants);
            match value.op {
                BinOp::Add(_) => left.checked_add(right).unwrap(),
                BinOp::Sub(_) => left.checked_sub(right).unwrap(),
                BinOp::Mul(_) => left.checked_mul(right).unwrap(),
                BinOp::Div(_) => left / right,
                BinOp::BitAnd(_) => left & right,
                _ => panic!("unsupported address arithmetic"),
            }
        },
        Expr::Unary(value) if matches!(value.op, syn::UnOp::Not(_)) => !evaluate(&value.expr, constants),
        _ => panic!("unsupported address initializer"),
    }
}

#[test]
fn provider_section_views_do_not_overlap_the_reserved_component_heap() {
    let mut constants = HashMap::new();
    for source in [
        include_str!("../../../components/ntos-executive/src/allocator.rs"),
        include_str!("../../../components/ntos-executive/src/provider_mm_section_objects.rs"),
    ] {
        for item in syn::parse_file(source).unwrap().items {
            if let Item::Const(item) = item {
                constants.insert(item.ident.to_string(), *item.expr);
            }
        }
    }
    let value = |name: &str| evaluate(&constants[name], &constants);
    let heap_end = value("HEAP_BASE").checked_add(value("HEAP_FRAMES") * 0x1000).unwrap();
    let start = value("VIEW_START");
    assert!(start >= heap_end,
        "Section arena {start:#x} overlaps reserved component heap ending at {heap_end:#x}");
    assert_eq!(start % value("TABLE_SIZE"), 0);
    assert!(start < value("VIEW_END"));
}

#[test]
fn root_heap_has_headroom_for_native_system_fold_staging() {
    let allocator = syn::parse_file(include_str!("../../../components/ntos-executive/src/allocator.rs")).unwrap();
    let mut constants = HashMap::new();
    for item in allocator.items {
        if let Item::Const(item) = item {
            constants.insert(item.ident.to_string(), *item.expr);
        }
    }
    let value = |name: &str| evaluate(&constants[name], &constants);
    let durable_bytes = (value("HEAP_FRAMES") - value("EXECUTIVE_TRANSIENT_HEAP_FRAMES")) * 0x1000;
    // The live LiberNT fold reached a 61,424,896-byte bump before allocating its
    // 1,792,428-byte SYSTEM image. Reserve room for that image, a second snapshot,
    // and subsequent boot work rather than admitting the fold at the terminal page.
    const OBSERVED_BUMP: u64 = 61_424_896;
    const SYSTEM_IMAGE: u64 = 1_792_428;
    const SNAPSHOT: u64 = 2_921_809;
    const BOOT_HEADROOM: u64 = 8 * 1024 * 1024;
    assert!(durable_bytes >= OBSERVED_BUMP + SYSTEM_IMAGE + SNAPSHOT + BOOT_HEADROOM);
}
