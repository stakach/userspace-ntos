//! A projected video source must keep its physical cache type at the win32k caller alias.

#[path = "../../../components/ntos-executive/src/hosted_video_pool_cache.rs"]
mod hosted_video_pool_cache;

use hosted_video_pool_cache::{page_map_rights, VideoAliasBackingCache};
use nt_hosted_runtime::ContiguousRamCachePolicy;
use syn::{visit::Visit, Expr, Item};

const RW_NX: u64 = 0b111;

#[test]
fn video_alias_rights_follow_the_retained_backing() {
    assert_eq!(page_map_rights(VideoAliasBackingCache::PoolRam, RW_NX), RW_NX);
    assert_eq!(
        page_map_rights(
            VideoAliasBackingCache::Contiguous(ContiguousRamCachePolicy::Cached),
            RW_NX,
        ),
        RW_NX,
    );
    assert_eq!(
        page_map_rights(
            VideoAliasBackingCache::Contiguous(ContiguousRamCachePolicy::Uncached),
            RW_NX,
        ),
        RW_NX | 0b1000,
        "the existing bare RW_NX PageMap would create a WB alias of the UC source",
    );
}

#[test]
fn production_video_alias_reads_the_pinned_source_cache() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/hosted_video_pool_map.rs",
    ))
    .unwrap();
    let parsed = syn::parse_file(&source).unwrap();
    let build = parsed
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "build_alias" => Some(function),
            _ => None,
        })
        .expect("native video alias builder");

    #[derive(Default)]
    struct Wiring {
        map_calls: usize,
        policy_calls: usize,
        backing_cache_reads: usize,
    }
    impl<'ast> Visit<'ast> for Wiring {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                match path.path.segments.last().unwrap().ident.to_string().as_str() {
                    "page_map_r" => self.map_calls += 1,
                    "page_map_rights" => self.policy_calls += 1,
                    _ => {}
                }
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "cache" {
                self.backing_cache_reads += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let mut wiring = Wiring::default();
    wiring.visit_item_fn(build);
    assert_eq!(wiring.map_calls, 1, "map one retained alias per frame");
    assert_eq!(wiring.policy_calls, 1, "derive native PageMap rights from the cache policy");
    assert_eq!(
        wiring.backing_cache_reads, 1,
        "the builder must read the retained pool/projection cache, not always choose WB",
    );
}
