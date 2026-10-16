//! Reviewed import inventories from the pinned installed LiberNT drivers.
//! CI has no release media; a locally staged release is checked against each fixture.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const REVISION: &str = "8e478a22a1e8f8a22bab17131f3184a7b4548c3d";

fn fixture(driver: &str) -> &'static str {
    match driver {
        "acpi.sys" => include_str!("../fixtures/libernt_acpi_native_imports.txt"),
        "basicdisplay.sys" => include_str!("../fixtures/libernt_basicdisplay_native_imports.txt"),
        "dxgkrnl.sys" => include_str!("../fixtures/libernt_dxgkrnl_native_imports.txt"),
        _ => panic!("unreviewed LiberNT driver {driver}"),
    }
}

pub fn imports(driver: &str, modules: &[&str]) -> BTreeSet<String> {
    let mut lines = fixture(driver).lines();
    assert_eq!(
        lines.next(),
        Some(format!("# LiberNT source revision {REVISION}").as_str()),
        "review the import fixture when the pinned release changes"
    );
    let expected: BTreeSet<(String, String)> = lines
        .map(|line| {
            let (module, name) = line.split_once(' ').expect("module and import name");
            assert!(!name.is_empty() && !name.contains(' '));
            (module.to_owned(), name.to_owned())
        })
        .collect();

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_path = root.join("rust-micro/vendor/libernt/manifest.txt");
    if manifest_path.exists() {
        let manifest = std::fs::read_to_string(manifest_path).expect("pinned LiberNT manifest");
        assert!(manifest.contains(&format!("source_revision={REVISION}")));
        let image = root
            .join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers")
            .join(driver);
        let bytes = std::fs::read(image).expect("locally staged pinned LiberNT driver");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned LiberNT PE");
        let actual: BTreeSet<(String, String)> = pe
            .imports()
            .expect("pinned LiberNT imports")
            .into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe")
                || dll.name.eq_ignore_ascii_case("hal.dll"))
            .flat_map(|dll| {
                let module = dll.name.to_ascii_lowercase();
                dll.functions.into_iter().map(move |entry| match entry {
                    ImportRef::ByName { name, .. } => (module.clone(), name),
                    ImportRef::ByOrdinal { ordinal, .. } => {
                        panic!("pinned {driver} imports {module} by ordinal {ordinal}")
                    }
                })
            })
            .collect();
        assert_eq!(actual, expected, "pinned {driver} import fixture changed");
    }

    expected
        .into_iter()
        .filter(|(module, _)| modules.iter().any(|wanted| module.eq_ignore_ascii_case(wanted)))
        .map(|(_, name)| name)
        .collect()
}
