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
