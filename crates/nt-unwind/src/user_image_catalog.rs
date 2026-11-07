//! Lazy, bounded admission of exact user mapped images for a single paused frame walk.
//!
//! The native source must authenticate the process generation, mapping owner and image bytes on
//! every load. This cache owns only immutable admitted snapshots; it does not extend the native
//! source's lifetime or prove that its mappings remain live while stack words are read.

use core::cell::RefCell;

use crate::{
    exception_images::{AdmittedExceptionImage, ExceptionImageCatalog},
    exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader},
    ImageReader, RuntimeFunction,
};

pub struct OnDemandUserImageCatalog<F> {
    images: RefCell<ExceptionImageCatalog>,
    source: F,
    max_images: usize,
}

impl<F> OnDemandUserImageCatalog<F>
where
    F: Fn(u64) -> Result<AdmittedExceptionImage, ExceptionImageError>,
{
    pub fn new(max_images: usize, source: F) -> Option<Self> {
        if max_images == 0 {
            return None;
        }
        let images = ExceptionImageCatalog::new(alloc::vec::Vec::new()).ok()?;
        Some(Self {
            images: RefCell::new(images),
            source,
            max_images,
        })
    }

    pub fn image_count(&self) -> usize {
        self.images.borrow().image_count()
    }
}

impl<F> ExceptionImageReader for OnDemandUserImageCatalog<F>
where
    F: Fn(u64) -> Result<AdmittedExceptionImage, ExceptionImageError>,
{
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        {
            let images = self.images.try_borrow().map_err(|_| ExceptionImageError::UnreadableImage)?;
            let found = images.lookup_exception_function(pc);
            if found.is_ok() {
                return found;
            }
            if images.images().iter().any(|image| {
                pc >= image.base() && pc - image.base() < image.size() as u64
            }) {
                return found;
            }
            if images.image_count() >= self.max_images {
                return Err(ExceptionImageError::UnreadableImage);
            }
        }
        let image = (self.source)(pc)?;
        // A source may prove some other mapped image; that does not admit this control PC.
        let result = image.lookup(pc)?;
        let mut images = self.images.try_borrow_mut().map_err(|_| ExceptionImageError::UnreadableImage)?;
        if images.image_count() >= self.max_images {
            return Err(ExceptionImageError::UnreadableImage);
        }
        images.append(image).map_err(|_| ExceptionImageError::UnreadableImage)?;
        Ok(result)
    }

    fn validate_collision_scope(&self, image_base: u64, handler_data: u64, index: u32) -> bool {
        self.images.try_borrow().is_ok_and(|images| {
            images.validate_collision_scope(image_base, handler_data, index)
        })
    }
}

impl<F> ImageReader for OnDemandUserImageCatalog<F>
where
    F: Fn(u64) -> Result<AdmittedExceptionImage, ExceptionImageError>,
{
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        match self.lookup_exception_function(pc).ok()? {
            ExceptionFunction::Function { image_base, function } => Some((image_base, function)),
            ExceptionFunction::Leaf => None,
        }
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        self.images.try_borrow().ok()?.read_u8(base, rva)
    }
}
