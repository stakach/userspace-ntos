use crate::MAX_PI;
use nt_exe_image::{HostedImageRoot, HostedProcessRole, OwnedHostedImageCatalog, SpawnTarget};

#[path = "../../../../components/ntos-executive/src/hosted_loaded_images.rs"]
mod hosted_loaded_images;

use hosted_loaded_images::HostedLoadedImageTable;

#[test]
fn stable_cache_entry_allocation_is_fallible_before_publication() {
    use syn::visit::Visit;
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/hosted_loaded_images.rs"
    )).unwrap();
    #[derive(Default)]
    struct AllocationAudit {
        registrations: usize,
        helper: bool,
    }
    #[derive(Default)]
    struct Registration {
        steps: Vec<&'static str>,
        infallible_box: bool,
    }
    impl<'ast> Visit<'ast> for Registration {
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            if let syn::Expr::Call(call) = &*expression.expr {
                if matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.last().unwrap().ident == "try_box_entry")
                {
                    self.steps.push("allocate");
                }
            }
            syn::visit::visit_expr_try(self, expression);
        }
        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*expression.func {
                let names: Vec<_> = path.path.segments.iter().map(|segment| segment.ident.to_string()).collect();
                self.infallible_box |= names.ends_with(&["Box".to_owned(), "new".to_owned()]);
            }
            syn::visit::visit_expr_call(self, expression);
        }
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.method == "push"
                && matches!(&*expression.receiver, syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "cache"))
            {
                self.steps.push("cache");
            }
            syn::visit::visit_expr_method_call(self, expression);
        }
        fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
            if matches!(&*expression.left, syn::Expr::Index(index)
                if matches!(&*index.expr, syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "attachments")))
            {
                self.steps.push("attachment");
            }
            syn::visit::visit_expr_assign(self, expression);
        }
    }
    impl<'ast> Visit<'ast> for AllocationAudit {
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if matches!(item.sig.ident.to_string().as_str(), "register_if_loaded" | "register_exact_loaded") {
                let mut audit = Registration::default();
                audit.visit_block(&item.block);
                assert!(!audit.infallible_box, "{} must return AllocationFailure, not invoke the OOM abort hook", item.sig.ident);
                assert_eq!(audit.steps, ["allocate", "cache", "attachment"],
                    "{} must reserve stable entry storage before publishing cache and target", item.sig.ident);
                self.registrations += 1;
            }
            syn::visit::visit_impl_item_fn(self, item);
        }
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == "try_box_entry" {
                struct Helper { nullable: bool, owned: bool, allocation: bool, abort: bool }
                impl<'ast> Visit<'ast> for Helper {
                    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                        self.nullable |= call.method == "is_null";
                        syn::visit::visit_expr_method_call(self, call);
                    }
                    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                        if let syn::Expr::Path(path) = &*call.func {
                            let last = path.path.segments.last().unwrap().ident.to_string();
                            self.owned |= last == "from_raw";
                            self.allocation |= last == "alloc";
                            self.abort |= matches!(last.as_str(), "handle_alloc_error" | "abort");
                        }
                        syn::visit::visit_expr_call(self, call);
                    }
                }
                let mut helper = Helper { nullable: false, owned: false, allocation: false, abort: false };
                helper.visit_block(&item.block);
                assert!(helper.nullable && helper.owned && helper.allocation && !helper.abort,
                    "stable Rust allocation must check failure before initializing Box ownership");
                self.helper = true;
            }
            syn::visit::visit_item_fn(self, item);
        }
    }
    let mut audit = AllocationAudit::default();
    audit.visit_file(&source);
    assert_eq!(audit.registrations, 2);
    assert!(audit.helper, "fallible stable cache entry allocator is required");
}

fn image_bytes(marker: u8) -> Vec<u8> {
    let mut bytes = vec![0; 0x400];
    for (offset, value) in [(0, 0x5a4du16), (0x44, 0x8664), (0x46, 1),
        (0x54, 0xf0), (0x56, 2), (0x58, 0x20b), (0x9c, 1)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(0x3c, 0x40u32), (0x40, 0x4550), (0x68, 0x1000),
        (0x78, 0x1000), (0x7c, 0x200), (0x90, 0x2000), (0x94, 0x200),
        (0xc4, 16), (0x150, 2), (0x154, 0x1000), (0x158, 0x200),
        (0x15c, 0x200), (0x16c, 0x6000_0020)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x70..0x78].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    bytes[0x148..0x150].copy_from_slice(b".text\0\0\0");
    bytes[0x200] = marker;
    bytes[0x201] = 0xc3;
    bytes
}

fn admit<const N: usize>(catalog: &mut OwnedHostedImageCatalog<N>) -> SpawnTarget {
    let pi = catalog.admit_dynamic_executable(
        b"ordinary.exe", HostedProcessRole::NativeApplication,
        b"\\SystemRoot\\System32\\ordinary.exe", b"ordinary.exe",
        HostedImageRoot::System32, MAX_PI,
    ).unwrap();
    SpawnTarget::from_image(catalog.get_by_pi(pi).unwrap())
}

#[test]
fn exact_snapshot_layout_preserves_each_raw_source_base_and_attachment_lifetime() {
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let first = admit(&mut catalog);
    let second = admit(&mut catalog);
    let mut table = HostedLoadedImageTable::new();
    assert!(table.reset(MAX_PI));
    let first_bytes = image_bytes(0x90);
    let mut second_bytes = image_bytes(0xcc);
    second_bytes[0x70..0x78].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
    table.register_exact_loaded(catalog.get_by_pi(first.pi).unwrap(), first_bytes.clone()).unwrap();
    table.register_exact_loaded(catalog.get_by_pi(second.pi).unwrap(), second_bytes.clone()).unwrap();
    let first_layout = table.layout_by_pi(first.pi).unwrap();
    let second_layout = table.layout_by_pi(second.pi).unwrap();
    assert_eq!((first_layout.base(), first_layout.size(), first_layout.entry()),
        (0x1_4000_0000, 0x2000, 0x1_4000_1000));
    assert_eq!((second_layout.base(), second_layout.size(), second_layout.entry()),
        (0x1_8000_0000, 0x2000, 0x1_8000_1000));
    table.retire_exact(first).unwrap();
    assert!(table.layout_by_pi(first.pi).is_none());
    assert_eq!(table.retire_exact_snapshot(first).unwrap(), first_bytes);
    assert_eq!(table.layout_by_pi(second.pi), Some(second_layout));
    table.retire_exact(second).unwrap();
    assert_eq!(table.retire_exact_snapshot(second).unwrap(), second_bytes);
}

#[test]
fn private_snapshot_release_requires_exact_detached_owner_and_consumes_once() {
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let first = admit(&mut catalog);
    let second = admit(&mut catalog);
    let mut table = HostedLoadedImageTable::new();
    assert!(table.reset(MAX_PI));
    let first_bytes = image_bytes(0x90);
    let second_bytes = image_bytes(0xcc);
    let second_address = second_bytes.as_ptr() as u64;
    table.register_exact_loaded(catalog.get_by_pi(first.pi).unwrap(), first_bytes.clone()).unwrap();
    table.register_exact_loaded(catalog.get_by_pi(second.pi).unwrap(), second_bytes).unwrap();
    assert!(table.retire_exact_snapshot(first).is_err(), "live pager attachment fences bytes");
    let mut stale = first;
    stale.generation += 1;
    assert!(table.retire_exact_snapshot(stale).is_err());
    table.retire_exact(first).unwrap();
    assert!(unsafe { table.pe_and_pool_by_leaf(b"ordinary.exe") }.is_none());
    assert_eq!(table.retire_exact_snapshot(first).unwrap(), first_bytes);
    assert!(table.retire_exact_snapshot(first).is_err());
    assert!(table.matches_target(second));
    assert_eq!(table.get_by_pi(second.pi).unwrap().pool_va(), second_address);
    assert!(unsafe { table.pe_by_pi(second.pi) }.is_some());
    assert_eq!(table.store_stats().2, 1, "retired private rows are not permanent cache entries");
    table.retire_exact(second).unwrap();
    assert_eq!(table.retire_exact_snapshot(second).unwrap()[0x200], 0xcc);
    assert_eq!(table.store_stats().2, 0);
}

#[test]
fn repeated_private_snapshots_do_not_accumulate_bytes_or_cache_rows() {
    let mut table = HostedLoadedImageTable::new();
    assert!(table.reset(MAX_PI));
    let mut catalog = OwnedHostedImageCatalog::<64>::new();
    for marker in 0..32 {
        let target = admit(&mut catalog);
        let expected = image_bytes(marker);
        table.register_exact_loaded(catalog.get_by_pi(target.pi).unwrap(), expected.clone()).unwrap();
        assert_eq!(table.store_stats().2, 1);
        table.retire_exact(target).unwrap();
        assert_eq!(table.retire_exact_snapshot(target).unwrap(), expected);
        assert_eq!(table.store_stats().2, 0);
        assert!(unsafe { table.pe_and_pool_by_leaf(b"ordinary.exe") }.is_none());
    }
}

#[test]
fn bootstrap_cache_is_not_released_as_a_process_private_snapshot() {
    let mut catalog = OwnedHostedImageCatalog::<1>::new();
    let target = admit(&mut catalog);
    let bytes = Box::leak(image_bytes(0x90).into_boxed_slice());
    let pe = nt_pe_loader::PeFile::parse(bytes).unwrap();
    let address = bytes.as_ptr() as u64;
    let mut table = HostedLoadedImageTable::new();
    assert!(table.reset(MAX_PI));
    table.register_if_loaded(catalog.get_by_pi(target.pi).unwrap(), Some(pe), address).unwrap();
    table.retire_exact(target).unwrap();
    assert!(table.retire_exact_snapshot(target).is_err());
    assert_eq!(table.store_stats().2, 1);
    assert_eq!(unsafe { table.pe_and_pool_by_leaf(b"ordinary.exe") }.unwrap().1, address);
}

#[test]
fn parsed_descriptor_addresses_survive_cache_growth_and_other_snapshot_retirement() {
    let mut catalog = OwnedHostedImageCatalog::<64>::new();
    let first = admit(&mut catalog);
    let mut table = HostedLoadedImageTable::new();
    assert!(table.reset(MAX_PI));
    table.register_exact_loaded(catalog.get_by_pi(first.pi).unwrap(), image_bytes(0x90)).unwrap();
    let original = unsafe { table.pe_by_pi(first.pi) }.unwrap() as *const _ as usize;
    let mut detached = Vec::new();
    for marker in 1..80 {
        let other = admit(&mut catalog);
        table.register_exact_loaded(catalog.get_by_pi(other.pi).unwrap(), image_bytes(marker)).unwrap();
        assert_eq!(unsafe { table.pe_by_pi(first.pi) }.unwrap() as *const _ as usize, original);
        table.retire_exact(other).unwrap();
        catalog.retire_dynamic_target(other).unwrap();
        detached.push(other);
    }
    for other in detached {
        table.retire_exact_snapshot(other).unwrap();
        assert_eq!(unsafe { table.pe_by_pi(first.pi) }.unwrap() as *const _ as usize, original);
    }
}

#[test]
fn exact_reader_lease_fences_detached_bytes_until_last_reader_acknowledgement() {
    let mut catalog = OwnedHostedImageCatalog::<1>::new();
    let target = admit(&mut catalog);
    let mut table = HostedLoadedImageTable::new();
    assert!(table.reset(MAX_PI));
    let bytes = image_bytes(0x90);
    table.register_exact_loaded(catalog.get_by_pi(target.pi).unwrap(), bytes.clone()).unwrap();
    let first = table.acquire_snapshot_reader(target).unwrap();
    let second = table.acquire_snapshot_reader(target).unwrap();
    let mut foreign = HostedLoadedImageTable::new();
    assert!(foreign.reset(MAX_PI));
    assert!(foreign.release_snapshot_reader(first).is_err());
    table.retire_exact(target).unwrap();
    assert!(table.acquire_snapshot_reader(target).is_err(), "detached owner admits no new reader");
    assert!(table.retire_exact_snapshot(target).is_err());
    table.release_snapshot_reader(first).unwrap();
    assert!(table.release_snapshot_reader(first).is_err(), "reader replay cannot release another reader");
    assert!(table.retire_exact_snapshot(target).is_err());
    table.release_snapshot_reader(second).unwrap();
    assert_eq!(table.retire_exact_snapshot(target).unwrap(), bytes);
    assert!(table.release_snapshot_reader(second).is_err());
}
