#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use core::str::from_utf8_unchecked;

const LEN_MAX_PATH: usize = 16;
const FILENAME_OFFSET: usize = 16;
const ARGNAME_OFFSET: usize = 24;
const ARG_NUMBER: usize = 1;

#[tracepoint]
pub fn tracepoint_test(ctx: TracePointContext) -> u32 {
    match try_tracepoint_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_test(ctx: TracePointContext) -> Result<u32, i64> {
    let mut buf = [0u8; LEN_MAX_PATH];
    let mut arg_buf = [0u8; 16];

    let filename = unsafe {
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_src_addr, &mut buf)?;
        from_utf8_unchecked(filename_bytes)
    };

    info!(
        &ctx,
        "tracepoint sys_enter_execve called. Binary: {}", filename
    );

    let argname = unsafe {
        let argv_ptr: *const *const u8 = ctx.read_at::<*const *const u8>(ARGNAME_OFFSET)?;
        //https://doc.rust-lang.org/core/primitive.pointer.html#method.add
        let argv1_ptr_ptr = argv_ptr.add(ARG_NUMBER);
        let argv1: *const u8 = bpf_probe_read_user(argv1_ptr_ptr)?;
        let arg_bytes = bpf_probe_read_user_str_bytes(argv1, &mut arg_buf)?;
        from_utf8_unchecked(arg_bytes)
    };
    info!(
        &ctx,
        "tracepoint sys_enter_execve called. arg1: {}", argname
    );
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
