//! Validate real PE metadata without executing or modifying the supplied images.
use nt_pe_loader::PeFile;
use nt_unwind::exception_images::AdmittedExceptionImage;
use std::{env, fs, process::ExitCode};

fn check(path: &std::ffi::OsStr) -> Result<(u64, usize, usize), String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let pe = PeFile::parse(&bytes).map_err(|error| format!("PE headers: {error:?}"))?;
    let base = pe.image_base();
    let mapped = pe
        .map(base)
        .map_err(|error| format!("mapping: {error:?}"))?;
    let image = AdmittedExceptionImage::from_mapped_image(base, mapped.bytes.into_boxed_slice())
        .map_err(|error| format!("exception admission: {error:?}"))?;
    Ok((image.base(), image.size(), image.function_count()))
}

fn main() -> ExitCode {
    let paths: Vec<_> = env::args_os().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: check_exception_images <image.sys|image.dll|image.exe> ...");
        return ExitCode::from(2);
    }
    let mut failed = false;
    for path in paths {
        match check(&path) {
            Ok((base, size, functions)) => println!(
                "PASS {} base={base:#x} bytes={size} functions={functions}",
                path.to_string_lossy()
            ),
            Err(error) => {
                eprintln!("FAIL {}: {error}", path.to_string_lossy());
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
