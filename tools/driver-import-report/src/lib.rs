//! Analyse a Windows `.sys` image: list its imports, resolve them against the
//! Driver Host's export set, and decide whether it can run under v0.1 (spec §15).

use std::fmt::Write;

use nt_compat_exports::{ExportRegistry, ImportOutcome, ImportReport};
use nt_pe_loader::{ImportRef, PeFile};

/// The result of analysing an image.
pub struct Analysis {
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub sections: Vec<String>,
    pub import_dlls: Vec<String>,
    pub report: ImportReport,
}

impl Analysis {
    /// True if every import resolves — the driver may be loaded.
    pub fn runnable(&self) -> bool {
        self.report.runnable()
    }
}

/// Parse + analyse `bytes` (a `.sys` image).
pub fn analyze(bytes: &[u8]) -> Result<Analysis, String> {
    let pe = PeFile::parse(bytes).map_err(|e| format!("PE parse failed: {e:?}"))?;
    let imports = pe
        .imports()
        .map_err(|e| format!("import table invalid: {e:?}"))?;

    let reg = ExportRegistry::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut import_dlls = Vec::new();
    for dll in &imports {
        import_dlls.push(dll.name.clone());
        for f in &dll.functions {
            let fname = match f {
                ImportRef::ByName { name, .. } => name.clone(),
                ImportRef::ByOrdinal { ordinal, .. } => format!("#{ordinal}"),
            };
            pairs.push((dll.name.clone(), fname));
        }
    }
    let report = reg.check(pairs.iter().map(|(d, n)| (d.as_str(), n.as_str())));

    Ok(Analysis {
        image_base: pe.image_base(),
        entry_rva: pe.entry_point_rva(),
        size_of_image: pe.size_of_image(),
        sections: pe
            .sections()
            .iter()
            .map(|s| s.name_str().to_string())
            .collect(),
        import_dlls,
        report,
    })
}

/// Render a human-readable report (spec §15).
pub fn render(a: &Analysis) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "image base : 0x{:x}", a.image_base);
    let _ = writeln!(s, "entry RVA  : 0x{:x}", a.entry_rva);
    let _ = writeln!(s, "image size : 0x{:x}", a.size_of_image);
    let _ = writeln!(s, "sections   : {}", a.sections.join(" "));
    let _ = writeln!(s, "import DLLs : {}", a.import_dlls.join(" "));
    let _ = writeln!(s, "imports:");
    for c in &a.report.checks {
        let (tag, detail) = match c.outcome {
            ImportOutcome::Available(st) => ("OK      ", st.as_str()),
            ImportOutcome::Blocked => ("UNSUPP  ", "Unsupported"),
            ImportOutcome::Missing => ("MISSING ", "(unknown)"),
        };
        let _ = writeln!(s, "  {tag} {}!{} -> {detail}", c.dll, c.name);
    }
    if a.runnable() {
        let _ = writeln!(s, "VERDICT: runnable");
    } else {
        let _ = writeln!(
            s,
            "BLOCKED: {} import(s) unavailable; v0.1 cannot run this driver",
            a.report.blocking().count()
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_driver_test_fixtures::{minimal_pe, pe_importing};

    #[test]
    fn no_import_image_is_runnable() {
        let a = analyze(&minimal_pe()).unwrap();
        assert_eq!(a.entry_rva, 0x1000);
        assert!(a.report.checks.is_empty());
        assert!(a.runnable());
    }

    #[test]
    fn supported_imports_are_runnable() {
        let bytes = pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoCreateSymbolicLink"]);
        let a = analyze(&bytes).unwrap();
        assert_eq!(a.import_dlls, vec!["ntoskrnl.exe"]);
        assert_eq!(a.report.checks.len(), 2);
        assert!(a.runnable());
    }

    #[test]
    fn unsupported_import_blocks() {
        let bytes = pe_importing("ntoskrnl.exe", &["IoCreateDevice", "IoConnectInterrupt"]);
        let a = analyze(&bytes).unwrap();
        assert!(!a.runnable());
        assert_eq!(a.report.blocking().count(), 1);
        assert!(render(&a).contains("BLOCKED:"));
    }

    #[test]
    fn garbage_is_a_clean_error() {
        assert!(analyze(&[1, 2, 3, 4]).is_err());
    }
}
