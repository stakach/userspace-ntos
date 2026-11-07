//! Boot 41154749647: caller-terminal metadata ACK used source-IRP operation 13,
//! which the new IoReuseIrp arm also matched. The ticket ID/generation (1/1)
//! were interpreted as an IRP pointer and NTSTATUS before the ACK arm ran.

use std::collections::BTreeSet;
use syn::{Expr, Item, Lit, Pat, Stmt};

const LEDGER: &str =
    include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
const EXPORTS: &str =
    include_str!("../../../components/ntos-executive/src/hosted_irp_lifecycle_exports.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn operation_values(pattern: &Pat) -> BTreeSet<u64> {
    match pattern {
        Pat::Lit(literal) => match &literal.lit {
            Lit::Int(value) => [value.base10_parse().expect("numeric service operation")]
                .into_iter().collect(),
            _ => panic!("unexpected service operation literal"),
        },
        Pat::Or(or) => or.cases.iter().flat_map(operation_values).collect(),
        Pat::Path(path) => {
            let name = path.path.segments.last().expect("named operation").ident.to_string();
            [lifecycle_operation(&name)].into_iter().collect()
        },
        Pat::Wild(_) => BTreeSet::new(),
        _ => panic!("service operation arm should use numeric literals"),
    }
}

fn lifecycle_operation(name: &str) -> u64 {
    let file = syn::parse_file(EXPORTS).expect("native lifecycle exports parse");
    let item = file.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == name => Some(item),
        _ => None,
    }).expect("native lifecycle service operation");
    let Expr::Lit(value) = &*item.expr else { panic!("lifecycle operation must be literal"); };
    let Lit::Int(value) = &value.lit else { panic!("lifecycle operation must be integer"); };
    value.base10_parse().expect("numeric lifecycle operation")
}

#[test]
fn source_irp_lifecycle_operations_cannot_shadow_terminal_ack() {
    let file = syn::parse_file(LEDGER).expect("source IRP ledger parses");
    let service = file.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "service" => Some(item),
        _ => None,
    }).expect("source IRP service");
    let Some(Stmt::Expr(Expr::Match(dispatch), _)) = service.block.stmts.last() else {
        panic!("source IRP service ends in operation dispatch");
    };
    let mut seen = BTreeSet::new();
    let mut mutation = None;
    for arm in &dispatch.arms {
        let values = operation_values(&arm.pat);
        for value in &values {
            assert!(seen.insert(*value), "source IRP operation {value} is shadowed by an earlier arm");
        }
        if let Expr::Call(call) = &*arm.body {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.is_ident("mutate_local_irp_packet")) {
                mutation = Some(values);
            }
        }
    }
    let mutation = mutation.expect("native IRP packet mutation arm");
    assert_eq!(mutation,
        [lifecycle_operation("INITIALIZE"), lifecycle_operation("REUSE")]
            .into_iter().collect());

    // The provider sends this exact ticket ACK after terminal source retirement.
    assert!(DRIVER.contains("            13,\n            entry.source_ticket_id,\n            entry.source_ticket_generation,\n            0,"),
        "caller-terminal ACK still uses operation 13 with ticket identity");
    assert!(!mutation.contains(&13), "IoReuseIrp must not consume the terminal ACK opcode");
}
