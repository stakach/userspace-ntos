//! A native preload refusal must identify the first failing stage and its exact subject.

#[test]
fn boot_source_preload_reports_first_failure_with_subject_and_status() {
    let source = std::env::var("PRELOAD_DIAGNOSTIC_SOURCE")
        .map(|path| std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|_| include_str!("../../../components/ntos-executive/src/hosted_driver_preload.rs").into());
    let report = &source[source.find("fn preload_failure(").expect("bounded preload failure reporter")
        ..source.find("fn dword(").expect("preload failure reporter boundary")];
    for field in ["[driver-preload-fail] stage=", " subject=", " status=0x"] {
        assert!(report.contains(field), "missing diagnostic field {field}");
    }
    for (stage, subject) in [
        ("service-query", "name.as_bytes()"),
        ("file-metadata", "path"),
        ("file-read", "path"),
        ("pe-imports", "path"),
        ("catalog-stage", "path"),
        ("class-filter-format", "class.name.as_bytes()"),
        ("final-generation", "b\"system\""),
    ] {
        assert!(source.contains(&format!("b\"{stage}\", {subject}")),
            "missing exact preload refusal {stage} / {subject}");
    }
}
