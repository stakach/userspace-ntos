//! Thread-local CRT state and x64 nonlocal control transfer.

use core::ffi::c_void;

/// MSVC's floating-point marker is a data export with this conventional value.
#[no_mangle]
pub static _fltused: i32 = 0x9875;

/// Wine's ntdll uses the low 32 bits of TEB TLS slot 16 for its CRT errno.
#[export_name = "_errno"]
pub extern "C" fn errno() -> *mut i32 {
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        let teb: usize;
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[0x30]",
                out(reg) teb,
                options(nostack, preserves_flags, readonly)
            )
        };
        (teb + nt_ntdll_layout::TEB_TLS_SLOTS_OFFSET as usize + 16 * 8) as *mut i32
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    {
        core::ptr::null_mut()
    }
}

// The x64 `_JUMP_BUFFER` offsets and callee-saved register set follow
// references/wine/dlls/ntdll/signal_x86_64.c and winnt.h.  Save the caller's
// return address and post-return RSP, never the stack state inside this entry.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
macro_rules! export_setjmp {
    ($rust_name:ident, $export:literal) => {
        #[unsafe(naked)]
        #[export_name = $export]
        pub unsafe extern "C" fn $rust_name(_buffer: *mut u8, _frame: *mut c_void) -> i32 {
            core::arch::naked_asm!(
                "mov [rcx], rdx",
                "mov [rcx + 0x08], rbx",
                "lea rax, [rsp + 0x08]",
                "mov [rcx + 0x10], rax",
                "mov [rcx + 0x18], rbp",
                "mov [rcx + 0x20], rsi",
                "mov [rcx + 0x28], rdi",
                "mov [rcx + 0x30], r12",
                "mov [rcx + 0x38], r13",
                "mov [rcx + 0x40], r14",
                "mov [rcx + 0x48], r15",
                "mov rax, [rsp]",
                "mov [rcx + 0x50], rax",
                "stmxcsr [rcx + 0x58]",
                "fnstcw [rcx + 0x5c]",
                "movdqu [rcx + 0x60], xmm6",
                "movdqu [rcx + 0x70], xmm7",
                "movdqu [rcx + 0x80], xmm8",
                "movdqu [rcx + 0x90], xmm9",
                "movdqu [rcx + 0xa0], xmm10",
                "movdqu [rcx + 0xb0], xmm11",
                "movdqu [rcx + 0xc0], xmm12",
                "movdqu [rcx + 0xd0], xmm13",
                "movdqu [rcx + 0xe0], xmm14",
                "movdqu [rcx + 0xf0], xmm15",
                "xor eax, eax",
                "ret",
            );
        }
    };
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
export_setjmp!(setjmp, "_setjmp");
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
export_setjmp!(setjmpex, "_setjmpex");

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
#[unsafe(naked)]
unsafe extern "C" fn longjmp_restore_regs(_buffer: *const c_void, _value: i32) -> ! {
    core::arch::naked_asm!(
        "mov eax, edx",
        "mov rbx, [rcx + 0x08]",
        "mov rbp, [rcx + 0x18]",
        "mov rsi, [rcx + 0x20]",
        "mov rdi, [rcx + 0x28]",
        "mov r12, [rcx + 0x30]",
        "mov r13, [rcx + 0x38]",
        "mov r14, [rcx + 0x40]",
        "mov r15, [rcx + 0x48]",
        "ldmxcsr [rcx + 0x58]",
        "fnclex",
        "fldcw [rcx + 0x5c]",
        "movdqu xmm6, [rcx + 0x60]",
        "movdqu xmm7, [rcx + 0x70]",
        "movdqu xmm8, [rcx + 0x80]",
        "movdqu xmm9, [rcx + 0x90]",
        "movdqu xmm10, [rcx + 0xa0]",
        "movdqu xmm11, [rcx + 0xb0]",
        "movdqu xmm12, [rcx + 0xc0]",
        "movdqu xmm13, [rcx + 0xd0]",
        "movdqu xmm14, [rcx + 0xe0]",
        "movdqu xmm15, [rcx + 0xf0]",
        "mov r8, [rcx + 0x50]",
        "mov rsp, [rcx + 0x10]",
        "jmp r8",
    );
}

#[repr(C)]
struct ExceptionRecord {
    code: u32,
    flags: u32,
    previous: *mut c_void,
    address: *mut c_void,
    parameter_count: u32,
    _padding: u32,
    information: [usize; 15],
}

/// On x64, a nonzero frame must execute intervening `__finally` handlers.
#[export_name = "longjmp"]
pub unsafe extern "C" fn longjmp(buffer: *const u8, value: i32) -> ! {
    let value = if value == 0 { 1 } else { value };
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    unsafe {
        let frame = core::ptr::read_unaligned(buffer as *const usize);
        if frame == 0 {
            longjmp_restore_regs(buffer.cast(), value)
        }
        let ip = core::ptr::read_unaligned(buffer.add(0x50) as *const usize);
        let mut record = ExceptionRecord {
            code: 0x8000_0026, // STATUS_LONGJUMP
            flags: 0,
            previous: core::ptr::null_mut(),
            address: core::ptr::null_mut(),
            parameter_count: 1,
            _padding: 0,
            information: [0; 15],
        };
        record.information[0] = buffer as usize;
        crate::exports::rtl_unwind(
            frame as *mut c_void,
            ip as *mut c_void,
            &mut record as *mut ExceptionRecord as *mut c_void,
            value as usize as *mut c_void,
        );
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    {
        let _ = (buffer, value);
    }
    // `RtlUnwind` must transfer control.  Trap if its frame is invalid.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("ud2", options(noreturn))
    }
    #[cfg(not(target_arch = "x86_64"))]
    loop {
        core::hint::spin_loop();
    }
}
