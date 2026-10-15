//! Retained image sources can outlive loader handles. Native readonly File ownership must not
//! impose a 64-body boot ceiling below the File ID representation's addressable capacity.

const MAIN: &str = include_str!("../../../../components/ntos-executive/src/main.rs");

fn assert_default_readonly_table(ty: &syn::Type, owner: &str) {
    let syn::Type::Path(ty) = ty else {
        panic!("{owner} must use the canonical readonly File table type");
    };
    let segment = ty.path.segments.last().expect("table type has a name");
    assert_eq!(segment.ident, "ReadOnlyFileOpenTable", "{owner}");
    assert!(
        matches!(segment.arguments, syn::PathArguments::None),
        "{owner} must use the dynamic/addressable default, not an artificial const slot ceiling"
    );
}

#[test]
fn readonly_file_storage_uses_addressable_default_capacity() {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let storage = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Static(item) if item.ident == "READONLY_FILE_OPEN_WORK" => Some(item),
            _ => None,
        })
        .expect("native readonly File storage must exist");
    assert_default_readonly_table(&storage.ty, "READONLY_FILE_OPEN_WORK");
}

#[test]
fn readonly_file_owner_uses_same_addressable_default_capacity() {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let owner = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "ExecReadOnlyFileOpens" => Some(item),
            _ => None,
        })
        .expect("native readonly File owner must exist");
    let field = owner
        .fields
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|name| name == "table"))
        .expect("native readonly File owner must retain its table");
    let syn::Type::Ptr(pointer) = &field.ty else {
        panic!("native readonly File owner must retain its canonical table pointer");
    };
    assert_default_readonly_table(&pointer.elem, "ExecReadOnlyFileOpens.table");
}
