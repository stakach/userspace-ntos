//! Compile the native boot reinitialization readiness predicate from production source.

use std::process::Command;

#[test]
fn queued_boot_callback_waits_for_publication_without_device_readiness() {
    let source = include_str!(
        "../../../components/ntos-executive/src/hosted_boot_driver_reinitialization.rs"
    );
    let start = source.find("pub(super) fn boot_ticket_matches_published_instance(").unwrap();
    let len = source[start..].find("\n}\n").unwrap() + 2;
    let predicate = &source[start..start + len];
    syn::parse_str::<syn::ItemFn>(predicate).expect("production readiness predicate parses");
    assert!(source.contains("boot_ticket_matches_published_instance(inst, identity)"),
        "boot drain must call the production readiness predicate");
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let publish = &launch[launch.find("impl LoadTail {").unwrap()..];
    let validation = publish.find("validate_hosted_driver_device_projections(&dc)").unwrap();
    let final_publication = publish.find("register_instance(&dc, published_claim)").unwrap();
    assert!(validation < final_publication);
    assert!(!publish[..validation].contains("driver_instances_mut()[instance].driver_object = drvobj"),
        "failed device validation must not expose a published DriverObject");

    let fixture = format!("{SUPPORT}\nmod production {{\nuse super::*;\n{predicate}\n}}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-boot-reinit-publication-{}", std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "production predicate must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    assert!(result.status.success(), "publication gate failed:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr));
}

const SUPPORT: &str = r#"
#[derive(Clone, Copy)] struct DriverInstance {
    ready: bool, driver_object: u64, domain_id: u64, domain_cookie: u64,
}
#[derive(Clone, Copy)] struct DomainId(u64);
impl DomainId { fn raw(self) -> u64 { self.0 } }
struct HostedDomainIdentity { domain_id: DomainId, cookie: u64 }
fn instance_domain_identity(inst: DriverInstance) -> Option<HostedDomainIdentity> {
    (inst.domain_id != 0 && inst.domain_cookie != 0).then_some(HostedDomainIdentity {
        domain_id: DomainId(inst.domain_id), cookie: inst.domain_cookie,
    })
}
mod nt_io_manager { pub mod driver_reinitialization {
    #[derive(Clone, Copy)] pub struct DriverReinitializationIdentity {
        pub driver_id: u64, pub domain_id: u64, pub domain_cookie: u64,
        pub driver_object: u64,
    }
} }
"#;

const CASES: &str = r#"
use nt_io_manager::driver_reinitialization::DriverReinitializationIdentity;
use production::boot_ticket_matches_published_instance;

#[test]
fn ticket_stays_queued_until_publication_even_if_device_ready_is_false() {
    let identity = DriverReinitializationIdentity {
        driver_id: 9, domain_id: 11, domain_cookie: 13, driver_object: 17,
    };
    let mut instance = DriverInstance {
        ready: false, driver_object: 0, domain_id: 11, domain_cookie: 13,
    };
    assert!(!boot_ticket_matches_published_instance(instance, identity));
    instance.driver_object = 17;
    assert!(boot_ticket_matches_published_instance(instance, identity));
    instance.driver_object += 1;
    assert!(!boot_ticket_matches_published_instance(instance, identity));
    instance.driver_object -= 1;
    instance.domain_cookie += 1;
    assert!(!boot_ticket_matches_published_instance(instance, identity));
}
"#;
