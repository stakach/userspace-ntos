//! Released ntdll floating-point CRT entry points.
//!
//! Keep the Windows x64 double ABI here; `libm` supplies the actual no-std
//! transcendental implementations so callers receive meaningful values.

#[export_name = "atan"]
pub extern "C" fn atan(value: f64) -> f64 {
    libm::atan(value)
}

#[export_name = "atan2"]
pub extern "C" fn atan2(y: f64, x: f64) -> f64 {
    libm::atan2(y, x)
}

#[export_name = "log"]
pub extern "C" fn log(value: f64) -> f64 {
    libm::log(value)
}

#[export_name = "pow"]
pub extern "C" fn pow(base: f64, exponent: f64) -> f64 {
    libm::pow(base, exponent)
}

#[export_name = "sqrt"]
pub extern "C" fn sqrt(value: f64) -> f64 {
    libm::sqrt(value)
}

#[export_name = "tan"]
pub extern "C" fn tan(value: f64) -> f64 {
    libm::tan(value)
}
