//! Native bootstrap must bind creator policy to each registered image's mounted File.

use syn::{Expr, Item, Member};
use nt_exe_image::{HostedImageRoot, HostedProcessRole, OwnedHostedImageCatalog,
    OwnedHostedProcessImage, RegisteredLaunchPolicyError, SpawnTarget};
use nt_memory_manager::{SectionFileIdentity, SectionMountIds};

const MANIFEST: &str = include_str!("../../../components/ntos-executive/src/hosted_bootstrap.rs");
const LOADER: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

fn field<'a>(fields: &'a syn::punctuated::Punctuated<syn::FieldValue, syn::token::Comma>, name: &str) -> &'a Expr {
    &fields.iter().find(|field| matches!(&field.member, Member::Named(ident) if ident == name))
        .unwrap_or_else(|| panic!("missing {name} policy field")).expr
}

fn last_path(expr: &Expr) -> String {
    let Expr::Path(path) = expr else { panic!("expected a policy enum path"); };
    path.path.segments.last().unwrap().ident.to_string()
}

#[test]
fn every_registered_bootstrap_image_carries_its_expected_creator() {
    let parsed = syn::parse_file(MANIFEST).unwrap();
    let entries = parsed.items.iter().find_map(|item| match item {
        Item::Const(value) if value.ident == "HOSTED_BOOTSTRAP_MANIFEST" => Some(value),
        _ => None,
    }).unwrap();
    let Expr::Array(array) = &*entries.expr else { panic!("bootstrap policy must be a fixed manifest"); };
    let expected = [
        ("CSRSS", "Win32Subsystem", "NativeSession"),
        ("WINLOGON", "InteractiveLogon", "NativeSession"),
        ("SERVICES", "ServiceControlManager", "InteractiveLogon"),
        ("LSASS", "LocalSecurityAuthority", "InteractiveLogon"),
        ("USERINIT", "InteractiveShellBootstrap", "InteractiveLogon"),
        ("EXPLORER", "InteractiveShell", "InteractiveShellBootstrap"),
    ];
    assert_eq!(array.elems.len(), expected.len());
    for (entry, (file, role, creator)) in array.elems.iter().zip(expected) {
        let Expr::Struct(entry) = entry else { panic!("bootstrap entry must be structured"); };
        assert_eq!(last_path(field(&entry.fields, "disk_path")), file);
        assert_eq!(last_path(field(&entry.fields, "role")), role);
        assert_eq!(last_path(field(&entry.fields, "allowed_creator")), creator);
    }
    let spec = MANIFEST.find("fn load_spec(self, pi: usize)").unwrap();
    let spec_tail = &MANIFEST[spec..MANIFEST[spec..].find("\n}\n").unwrap() + spec];
    assert!(spec_tail.contains("allowed_creator: self.allowed_creator"),
        "loader spec must carry the same manifest creator policy");
}

#[test]
fn loader_binds_policy_only_after_the_exact_mounted_file() {
    let start = LOADER.find("unsafe fn load_hosted_bootstrap_image(").unwrap();
    let end = LOADER[start..].find("loaded-table-begin").unwrap() + start;
    let body = &LOADER[start..end];
    let metadata = body.find("fat_open_path_metadata(&fs, spec.disk_path)").unwrap();
    let identity = body.find("exec_fs_file_identity(entry.metadata.file_id)").unwrap();
    let backing = body.find("catalog.bind_registered_backing(").unwrap();
    let policy = body.find("catalog.bind_registered_launch_policy(").expect("registered creator policy must bind");
    assert!(metadata < identity && identity < backing && backing < policy);
    assert!(body[backing..policy].contains("backing.expect("),
        "registered backing must be the mounted File, not a path or image name");
    assert!(body[policy..].contains("spec.allowed_creator"),
        "policy must come from the manifest entry");
}

#[test]
fn registered_creator_policy_rejects_missing_or_invalid_file_backing() {
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let image = OwnedHostedProcessImage::new(0, 1, 1, b"child.exe", b"child.exe",
        HostedProcessRole::InteractiveLogon, b"child.exe", b"child.exe",
        HostedImageRoot::System32, b"child").unwrap();
    catalog.register(image).unwrap();
    let target = SpawnTarget::from_image(catalog.get_by_pi(0).unwrap());
    assert_eq!(catalog.bind_registered_launch_policy(target, HostedProcessRole::NativeSession),
        Err(RegisteredLaunchPolicyError::MissingBacking));
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    assert!(catalog.bind_registered_backing(target,
        SectionFileIdentity { mount, file_id: 0 }).is_err());
    let file = SectionFileIdentity { mount, file_id: 33 };
    catalog.bind_registered_backing(target, file).unwrap();
    catalog.bind_registered_launch_policy(target, HostedProcessRole::NativeSession).unwrap();
    assert_eq!(catalog.registered_launch_policy(target),
        Some((file, HostedProcessRole::NativeSession)));
}
