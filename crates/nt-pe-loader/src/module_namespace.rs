//! Checked import namespaces and recursive dependency admission.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn module(name: &str, base: u64, target: ExportTarget) -> ImageExports {
        ImageExports {
            name: module_leaf(name).unwrap(),
            base,
            size: 0x1000,
            exports: vec![NamedExport {
                name: "Entry".into(),
                ordinal: 7,
                target,
            }],
        }
    }

    #[test]
    fn unknown_dll_never_resolves_against_core_exports() {
        assert_eq!(
            resolve(&[], "unknown.dll", &Symbol::Name("Entry".into())),
            Err(NamespaceError::MissingModule)
        );
        assert_eq!(core_role("ntoskrnl.exe"), Some(CoreRole::Kernel));
        assert_eq!(core_role("hal.dll"), Some(CoreRole::Hal));
        assert_eq!(core_role("notntoskrnl.exe"), None);
        assert_eq!(core_role("win32k.sys"), None);
    }

    #[test]
    fn extensionless_core_forwarders_preserve_the_registered_role() {
        for (name, role) in [
            ("NTOSKRNL", CoreRole::Kernel),
            ("ntkrnlmp", CoreRole::Kernel),
            ("NTKRNLPA", CoreRole::Kernel),
            ("ntkrpamp", CoreRole::Kernel),
            ("HAL", CoreRole::Hal),
        ] {
            let images = vec![module(
                "helper.dll",
                0x10000,
                ExportTarget::Forwarder(alloc::format!("{name}.Entry")),
            )];
            assert_eq!(
                resolve_with_core(
                    &images,
                    "helper.dll",
                    &Symbol::Name("Entry".into()),
                    |actual, symbol| (actual == role && *symbol == Symbol::Name("Entry".into()))
                        .then_some(0x12340)
                ),
                Ok(0x12340),
                "forwarder module {name}",
            );
        }
        for unknown in ["unknownmodule", "unknownmodule.dll", "ntoskrnl.dll"] {
            let images = vec![module(
                "helper.dll",
                0x10000,
                ExportTarget::Forwarder(alloc::format!("{unknown}.Entry")),
            )];
            assert_eq!(
                resolve_with_core(
                    &images,
                    "helper.dll",
                    &Symbol::Name("Entry".into()),
                    |_, _| panic!("unknown module must not enter the core namespace")
                ),
                Err(NamespaceError::MissingModule),
            );
        }
    }

    #[test]
    fn dxgthk_win32k_forwarder_uses_the_admitted_provider_image() {
        let images = vec![
            module(
                "dxgthk.sys",
                0x10000,
                ExportTarget::Forwarder("win32k.Entry".into()),
            ),
            module("win32k.sys", 0x20000, ExportTarget::Rva(0x200)),
        ];
        assert_eq!(
            resolve_with_core(
                &images,
                "dxgthk.sys",
                &Symbol::Name("Entry".into()),
                |_, _| panic!("win32k is an admitted provider image, not the core kernel")
            ),
            Ok(0x20200),
        );
    }

    #[test]
    fn exports_come_from_the_actual_named_image() {
        let images = vec![
            module("first.dll", 0x10000, ExportTarget::Rva(0x100)),
            module("second.dll", 0x20000, ExportTarget::Rva(0x200)),
        ];
        assert_eq!(
            resolve(&images, "SECOND.DLL", &Symbol::Name("Entry".into())),
            Ok(0x20200)
        );
        assert_eq!(
            resolve(&images, "first.dll", &Symbol::Ordinal(7)),
            Ok(0x10100)
        );
        assert_eq!(
            resolve(&images, "first.dll", &Symbol::Name("entry".into())),
            Err(NamespaceError::MissingExport)
        );
    }

    #[test]
    fn forwarders_resolve_real_modules_and_reject_cycles() {
        let mut images = vec![
            module(
                "first.dll",
                0x10000,
                ExportTarget::Forwarder("second.Entry".into()),
            ),
            module("second.dll", 0x20000, ExportTarget::Rva(0x200)),
        ];
        assert_eq!(
            resolve(&images, "first.dll", &Symbol::Name("Entry".into())),
            Ok(0x20200)
        );
        images[1].exports[0].target = ExportTarget::Forwarder("first.#7".into());
        assert_eq!(
            resolve(&images, "first.dll", &Symbol::Ordinal(7)),
            Err(NamespaceError::Cycle)
        );
    }

    #[test]
    fn dependency_stack_rejects_cycles_without_discarding_ancestors() {
        let mut stack = DependencyStack::default();
        stack.enter("first.dll").unwrap();
        stack.enter("second.dll").unwrap();
        assert_eq!(stack.enter("FIRST.DLL"), Err(NamespaceError::Cycle));
        assert_eq!(
            stack.leave("first.dll"),
            Err(NamespaceError::IdentityMismatch)
        );
        stack.leave("second.dll").unwrap();
        stack.leave("first.dll").unwrap();
        stack.enter("first.dll").unwrap();
    }

    #[test]
    fn path_and_export_extent_checks_fail_closed() {
        assert_eq!(
            module_leaf("../first.dll"),
            Err(NamespaceError::InvalidName)
        );
        assert_eq!(
            module_leaf("x\\first.dll"),
            Err(NamespaceError::InvalidName)
        );
        let images = vec![module("first.dll", 0x10000, ExportTarget::Rva(0x1000))];
        assert_eq!(
            resolve(&images, "first.dll", &Symbol::Ordinal(7)),
            Err(NamespaceError::InvalidExport)
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRole {
    Kernel,
    Hal,
}

pub fn core_role(name: &str) -> Option<CoreRole> {
    let name = module_leaf(name).ok()?;
    match name.as_str() {
        "ntoskrnl.exe" | "ntkrnlmp.exe" | "ntkrnlpa.exe" | "ntkrpamp.exe" => Some(CoreRole::Kernel),
        "hal.dll" => Some(CoreRole::Hal),
        _ => None,
    }
}

/// Normalize PE forwarder basenames without widening explicit import namespaces.
pub fn forwarder_module(name: &str) -> Result<String, NamespaceError> {
    let mut module = module_leaf(name)?;
    if !module.contains('.') {
        let suffix = match module.as_str() {
            "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp" => ".exe",
            "win32k" => ".sys",
            _ => ".dll",
        };
        module.push_str(suffix);
    }
    Ok(module)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceError {
    InvalidName,
    MissingModule,
    MissingExport,
    InvalidExport,
    Cycle,
    IdentityMismatch,
}

pub fn module_leaf(name: &str) -> Result<String, NamespaceError> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        || name == "."
        || name == ".."
    {
        return Err(NamespaceError::InvalidName);
    }
    Ok(name.to_ascii_lowercase())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Symbol {
    Name(String),
    Ordinal(u16),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    Rva(u32),
    Forwarder(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedExport {
    pub name: String,
    pub ordinal: u16,
    pub target: ExportTarget,
}
#[derive(Clone, Debug)]
pub struct ImageExports {
    pub name: String,
    pub base: u64,
    pub size: u32,
    pub exports: Vec<NamedExport>,
}

impl ImageExports {
    /// Parse all ordinal and named exports from a checked mapped image, not raw file offsets.
    pub fn from_mapped(name: &str, base: u64, bytes: &[u8]) -> Result<Self, NamespaceError> {
        let pe = crate::PeFile::parse(bytes).map_err(|_| NamespaceError::InvalidExport)?;
        let size = pe.size_of_image();
        if size as usize > bytes.len() || base.checked_add(u64::from(size)).is_none() {
            return Err(NamespaceError::InvalidExport);
        }
        let mut image = Self {
            name: module_leaf(name)?,
            base,
            size,
            exports: Vec::new(),
        };
        let Some((offset, length)) =
            crate::image_directory_entry(bytes, true, crate::DIRECTORY_ENTRY_EXPORT)
                .map_err(|_| NamespaceError::InvalidExport)?
        else {
            return Ok(image);
        };
        let bytes = &bytes[..size as usize];
        fn word(bytes: &[u8], offset: usize) -> Result<u32, NamespaceError> {
            let end = offset.checked_add(4).ok_or(NamespaceError::InvalidExport)?;
            Ok(u32::from_le_bytes(
                bytes
                    .get(offset..end)
                    .ok_or(NamespaceError::InvalidExport)?
                    .try_into()
                    .unwrap(),
            ))
        }
        fn text(bytes: &[u8], offset: usize, end: usize) -> Result<String, NamespaceError> {
            let tail = bytes
                .get(offset..end)
                .ok_or(NamespaceError::InvalidExport)?;
            let length = tail
                .iter()
                .position(|c| *c == 0)
                .ok_or(NamespaceError::InvalidExport)?;
            core::str::from_utf8(&tail[..length])
                .map(ToString::to_string)
                .map_err(|_| NamespaceError::InvalidExport)
        }
        if length < 40 {
            return Err(NamespaceError::InvalidExport);
        }
        let ordinal = word(bytes, offset + 16)?;
        let count = word(bytes, offset + 20)? as usize;
        let names = word(bytes, offset + 24)? as usize;
        let functions = word(bytes, offset + 28)? as usize;
        let name_table = word(bytes, offset + 32)? as usize;
        let ordinal_table = word(bytes, offset + 36)? as usize;
        if count > 65536 || names > 65536 {
            return Err(NamespaceError::InvalidExport);
        }
        let export_end = offset
            .checked_add(length as usize)
            .ok_or(NamespaceError::InvalidExport)?;
        for index in 0..count {
            let rva = word(
                bytes,
                functions
                    .checked_add(index * 4)
                    .ok_or(NamespaceError::InvalidExport)?,
            )?;
            if rva == 0 {
                continue;
            }
            if rva >= size {
                return Err(NamespaceError::InvalidExport);
            }
            let target = if (offset..export_end).contains(&(rva as usize)) {
                ExportTarget::Forwarder(text(bytes, rva as usize, export_end)?)
            } else {
                ExportTarget::Rva(rva)
            };
            let ordinal = ordinal
                .checked_add(index as u32)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(NamespaceError::InvalidExport)?;
            image.exports.push(NamedExport {
                name: String::new(),
                ordinal,
                target,
            });
        }
        for index in 0..names {
            let name_rva = word(
                bytes,
                name_table
                    .checked_add(index * 4)
                    .ok_or(NamespaceError::InvalidExport)?,
            )?;
            let at = ordinal_table
                .checked_add(index * 2)
                .ok_or(NamespaceError::InvalidExport)?;
            let function_index = u16::from_le_bytes(
                bytes
                    .get(at..at.checked_add(2).ok_or(NamespaceError::InvalidExport)?)
                    .ok_or(NamespaceError::InvalidExport)?
                    .try_into()
                    .unwrap(),
            ) as u32;
            if function_index as usize >= count {
                return Err(NamespaceError::InvalidExport);
            }
            let named_ordinal = ordinal
                .checked_add(function_index)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(NamespaceError::InvalidExport)?;
            let export = image
                .exports
                .iter_mut()
                .find(|export| export.ordinal == named_ordinal)
                .ok_or(NamespaceError::InvalidExport)?;
            let mut named = export.clone();
            named.name = text(bytes, name_rva as usize, bytes.len())?;
            image.exports.push(named);
        }
        Ok(image)
    }
}

pub fn resolve(
    images: &[ImageExports],
    module: &str,
    symbol: &Symbol,
) -> Result<u64, NamespaceError> {
    resolve_with_core(images, module, symbol, |_, _| None)
}

/// Core exports are selected only through an explicit registered kernel/HAL role.
pub fn resolve_with_core<F: FnMut(CoreRole, &Symbol) -> Option<u64>>(
    images: &[ImageExports],
    module: &str,
    symbol: &Symbol,
    mut core: F,
) -> Result<u64, NamespaceError> {
    fn walk<F: FnMut(CoreRole, &Symbol) -> Option<u64>>(
        images: &[ImageExports],
        module: String,
        symbol: Symbol,
        seen: &mut Vec<(String, Symbol)>,
        core: &mut F,
    ) -> Result<u64, NamespaceError> {
        if seen
            .iter()
            .any(|pair| pair == &(module.clone(), symbol.clone()))
        {
            return Err(NamespaceError::Cycle);
        }
        seen.push((module.clone(), symbol.clone()));
        if let Some(role) = core_role(&module) {
            return core(role, &symbol)
                .filter(|address| *address != 0)
                .ok_or(NamespaceError::MissingExport);
        }
        let image = images
            .iter()
            .find(|image| image.name == module)
            .ok_or(NamespaceError::MissingModule)?;
        let export = image
            .exports
            .iter()
            .find(|export| match &symbol {
                Symbol::Name(name) => export.name == *name,
                Symbol::Ordinal(n) => export.ordinal == *n,
            })
            .ok_or(NamespaceError::MissingExport)?;
        match &export.target {
            ExportTarget::Rva(rva) => {
                if *rva == 0 || *rva >= image.size {
                    return Err(NamespaceError::InvalidExport);
                }
                image
                    .base
                    .checked_add(u64::from(*rva))
                    .ok_or(NamespaceError::InvalidExport)
            }
            ExportTarget::Forwarder(value) => {
                let (dll, target) = value
                    .rsplit_once('.')
                    .ok_or(NamespaceError::InvalidExport)?;
                let dll = forwarder_module(dll)?;
                let target = if let Some(n) = target.strip_prefix('#') {
                    Symbol::Ordinal(n.parse().map_err(|_| NamespaceError::InvalidExport)?)
                } else {
                    if target.is_empty() {
                        return Err(NamespaceError::InvalidExport);
                    }
                    Symbol::Name(target.to_string())
                };
                walk(images, dll, target, seen, core)
            }
        }
    }
    walk(
        images,
        module_leaf(module)?,
        symbol.clone(),
        &mut Vec::new(),
        &mut core,
    )
}

#[derive(Default)]
pub struct DependencyStack {
    loading: Vec<String>,
}
impl DependencyStack {
    pub fn enter(&mut self, name: &str) -> Result<(), NamespaceError> {
        let name = module_leaf(name)?;
        if self.loading.contains(&name) {
            return Err(NamespaceError::Cycle);
        }
        self.loading.push(name);
        Ok(())
    }
    pub fn leave(&mut self, name: &str) -> Result<(), NamespaceError> {
        let name = module_leaf(name)?;
        if self.loading.last() != Some(&name) {
            return Err(NamespaceError::IdentityMismatch);
        }
        self.loading.pop();
        Ok(())
    }
}
