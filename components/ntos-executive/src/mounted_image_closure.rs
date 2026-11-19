//! Retained acquisition of a system image's dependency closure through the mounted volume.
//!
//! Every image in the closure is read by a `MountedSystemImageRead` owner (exact CREATE,
//! QUERY, READ and cleanup IRPs) into a byte catalog. PE mapping begins only after the
//! dependency snapshots are complete, so a missing forwarder cannot cause a second mapping
//! effect on retry. The owner of this closure decides what the mapped root becomes.

use alloc::{string::String, vec::Vec};
use nt_pe_loader::{
    module_namespace::{self, ExportTarget, ImageExports, Symbol},
    system_image_load_plan::{LoadAction, LoadPlanError, SystemImageLoadPlan},
    ImportRef, PeFile,
};

use crate::{
    mounted_system_image_read::{MountedSystemImageRead, SnapshotStep},
    win32k_glue::image_loader::{self, ImageSnapshot},
    win32k_seh_image,
};

const INVALID: u32 = 0xc000_000d;
const RESOURCES: u32 = 0xc000_009a;
const CANCELLED: u32 = 0xc000_0120;
const INVALID_IMAGE: u32 = 0xc000_007b;

fn plan_error_status(error: LoadPlanError) -> u32 {
    match error {
        LoadPlanError::NoCapacity => RESOURCES,
        LoadPlanError::InvalidName | LoadPlanError::WrongCompletion | LoadPlanError::Cycle => {
            INVALID_IMAGE
        }
    }
}

pub(crate) enum ClosureStep {
    Progress,
    Wait,
    /// A native effect has an uncertain result; the owner must retain this closure.
    Indeterminate,
    /// Terminal failure. Images mapped before it remain counted by `mapped_effect`.
    Failed(u32),
    /// Every image in the closure, the root included, is mapped from the catalog.
    Mapped,
}

#[must_use = "retain through every mounted File read and native map effect"]
pub(crate) struct MountedImageClosure {
    root: String,
    plan: SystemImageLoadPlan,
    catalog: Vec<ImageSnapshot>,
    read: Option<(String, MountedSystemImageRead)>,
    mapped_effect: bool,
    cancelled: bool,
}

impl MountedImageClosure {
    pub(crate) fn new(root: &str) -> Result<Self, u32> {
        let plan = SystemImageLoadPlan::new(root).map_err(|_| INVALID)?;
        let root = module_namespace::module_leaf(root).map_err(|_| INVALID)?;
        Ok(Self {
            root, plan, catalog: Vec::new(), read: None, mapped_effect: false, cancelled: false,
        })
    }

    pub(crate) fn root(&self) -> &str { &self.root }
    pub(crate) fn catalog(&self) -> &[ImageSnapshot] { &self.catalog }
    /// A native map effect has been committed; it has no teardown operation yet.
    pub(crate) fn mapped_effect(&self) -> bool { self.mapped_effect }
    /// A mounted File owner holds exact I/O that must drain before cancellation completes.
    pub(crate) fn reading(&self) -> bool { self.read.is_some() }

    pub(crate) unsafe fn request_cancel(&mut self) {
        self.cancelled = true;
        if let Some((_, read)) = self.read.as_mut() { read.request_cancel(); }
    }

    pub(crate) unsafe fn advance(&mut self, pml4: u64) -> ClosureStep {
        if let Some((name, read)) = self.read.as_mut() {
            return match read.advance() {
                SnapshotStep::Progress => ClosureStep::Progress,
                SnapshotStep::Wait => ClosureStep::Wait,
                SnapshotStep::Indeterminate => ClosureStep::Indeterminate,
                SnapshotStep::Ready(result) => {
                    let name = core::mem::take(name);
                    self.read = None;
                    match result {
                        Ok(snapshot) => self.file_ready(name, snapshot.path, snapshot.bytes),
                        Err(status) => ClosureStep::Failed(status),
                    }
                }
            };
        }
        if self.cancelled { return ClosureStep::Failed(CANCELLED); }
        match self.plan.next() {
            Some(LoadAction::ReadMountedFile(name)) => {
                if image_loader::loaded_image(&name, pml4) {
                    return if self.plan.skip_loaded(&name).is_err() {
                        ClosureStep::Indeterminate
                    } else {
                        ClosureStep::Progress
                    };
                }
                if let Some(snapshot) = snapshot(&self.catalog, &name) {
                    return match dependencies(&snapshot.bytes) {
                        Ok(dependencies) => self.dependencies_ready(&name, &dependencies),
                        Err(status) => ClosureStep::Failed(status),
                    };
                }
                match MountedSystemImageRead::new(&name) {
                    Ok(read) => {
                        self.read = Some((name, read));
                        ClosureStep::Progress
                    }
                    Err(status) => ClosureStep::Failed(status),
                }
            }
            Some(LoadAction::Map(name)) => match preflight_map(&name, pml4, &self.catalog) {
                Ok(Some(missing)) => {
                    if self.plan.require_dependency(&name, &missing).is_err() {
                        ClosureStep::Failed(INVALID_IMAGE)
                    } else {
                        ClosureStep::Progress
                    }
                }
                Ok(None) => match image_loader::load_installed_from_catalog(
                    &name, pml4, &self.catalog,
                ) {
                    Err(error) => ClosureStep::Failed(error.ntstatus() as u32),
                    Ok(_) => {
                        self.mapped_effect = true;
                        if self.plan.mapped(&name).is_err() {
                            ClosureStep::Indeterminate
                        } else {
                            ClosureStep::Progress
                        }
                    }
                },
                Err(status) => ClosureStep::Failed(status),
            },
            None => ClosureStep::Mapped,
        }
    }

    fn dependencies_ready(&mut self, name: &str, dependencies: &[String]) -> ClosureStep {
        let names: Vec<&str> = dependencies.iter().map(String::as_str).collect();
        match self.plan.file_ready(name, &names) {
            Ok(()) => ClosureStep::Progress,
            Err(error) => ClosureStep::Failed(plan_error_status(error)),
        }
    }

    fn file_ready(&mut self, name: String, path: Vec<u8>, mut bytes: Vec<u8>) -> ClosureStep {
        let dependencies = match dependencies(&bytes) {
            Ok(dependencies) => dependencies,
            Err(status) => return ClosureStep::Failed(status),
        };
        if let step @ ClosureStep::Failed(_) = self.dependencies_ready(&name, &dependencies) {
            return step;
        }
        if self.catalog.try_reserve(1).is_err() {
            bytes.clear();
            return ClosureStep::Failed(RESOURCES);
        }
        self.catalog.push(ImageSnapshot { name, path, bytes });
        ClosureStep::Progress
    }
}

fn snapshot<'a>(catalog: &'a [ImageSnapshot], name: &str) -> Option<&'a ImageSnapshot> {
    catalog.iter().find(|snapshot| snapshot.name == name)
}

fn dependencies(bytes: &[u8]) -> Result<Vec<String>, u32> {
    let pe = PeFile::parse(bytes).map_err(|_| INVALID_IMAGE)?;
    pe.imports().map_err(|_| INVALID_IMAGE)?.into_iter().map(|dll| {
        module_namespace::module_leaf(&dll.name).map_err(|_| INVALID_IMAGE)
    }).collect()
}

unsafe fn exports_for(name: &str, pml4: u64) -> Result<Option<ImageExports>, u32> {
    if name == "win32k.sys" {
        return win32k_seh_image::win32k_exports(pml4).map(Some).ok_or(0xc000_00a3u32);
    }
    Ok(image_loader::loaded_exports(name, pml4))
}

/// Inspect the exact imported symbol's forwarder chain before any native map effect. An
/// unacquired target becomes another `SystemImageLoadPlan` read/map action.
unsafe fn missing_forwarder(
    module: &str, symbol: Symbol, pml4: u64, seen: &mut Vec<(String, Symbol)>,
) -> Result<Option<String>, u32> {
    let module = module_namespace::module_leaf(module).map_err(|_| INVALID_IMAGE)?;
    if seen.len() >= 64 || seen.iter().any(|pair| pair.0 == module && pair.1 == symbol) {
        return Err(INVALID_IMAGE);
    }
    seen.push((module.clone(), symbol.clone()));
    if module_namespace::core_role(&module).is_some() { return Ok(None); }
    let Some(exports) = exports_for(&module, pml4)? else { return Ok(Some(module)); };
    let export = exports.exports.iter().find(|export| match &symbol {
        Symbol::Name(name) => export.name == *name,
        Symbol::Ordinal(ordinal) => export.ordinal == *ordinal,
    }).ok_or(0xc000_0139u32)?;
    let ExportTarget::Forwarder(target) = &export.target else { return Ok(None); };
    let (module, name) = target.rsplit_once('.').ok_or(INVALID_IMAGE)?;
    let module = module_namespace::forwarder_module(module).map_err(|_| INVALID_IMAGE)?;
    if !image_loader::loaded_image(&module, pml4) && module != "win32k.sys"
        && module_namespace::core_role(&module).is_none()
    {
        return Ok(Some(module));
    }
    let symbol = if let Some(ordinal) = name.strip_prefix('#') {
        Symbol::Ordinal(ordinal.parse().map_err(|_| INVALID_IMAGE)?)
    } else {
        Symbol::Name(String::from(name))
    };
    missing_forwarder(&module, symbol, pml4, seen)
}

unsafe fn preflight_map(
    name: &str, pml4: u64, catalog: &[ImageSnapshot],
) -> Result<Option<String>, u32> {
    let Some(source) = snapshot(catalog, name) else { return Err(0xc000_0034u32); };
    let pe = PeFile::parse(&source.bytes).map_err(|_| INVALID_IMAGE)?;
    for dll in pe.imports().map_err(|_| INVALID_IMAGE)? {
        for function in dll.functions {
            let symbol = match function {
                ImportRef::ByName { name, .. } => Symbol::Name(name),
                ImportRef::ByOrdinal { ordinal, .. } => Symbol::Ordinal(ordinal),
            };
            if let Some(missing) = missing_forwarder(&dll.name, symbol, pml4, &mut Vec::new())? {
                return Ok(Some(missing));
            }
        }
    }
    Ok(None)
}
