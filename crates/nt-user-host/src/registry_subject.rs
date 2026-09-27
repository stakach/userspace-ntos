//! Registry compatibility name for the general native caller subject.

pub type RegistrySubject = crate::native_caller_subject::NativeCallerSubject;

#[cfg(test)]
#[path = "registry_subject_tests.rs"]
mod tests;
