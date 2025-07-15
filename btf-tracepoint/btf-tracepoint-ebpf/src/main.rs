#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::info;

#[allow(
    clippy::all,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
)]
#[rustfmt::skip]
mod bindings;
use bindings::linux_binprm;

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

fn try_sched_process_exec(ctx: BtfTracePointContext) -> Result<i32, i64> {
    unsafe {
        let linux_binprm: *const linux_binprm = ctx.arg(2);
        let linux_binprm: &linux_binprm = &*linux_binprm;

        let mut buf = [0u8; 32];
        let filename_ptr = linux_binprm.filename as *const u8;
        let filename = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut buf)
            .map(|s| core::str::from_utf8_unchecked(s))?;

        info!(&ctx, "tracepoint sched_process_exec called {}", filename);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
