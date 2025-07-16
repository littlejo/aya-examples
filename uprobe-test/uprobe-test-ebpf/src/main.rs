#![no_std]
#![no_main]

use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;
use core::str::from_utf8_unchecked;

#[uprobe]
pub fn uprobe_test(ctx: ProbeContext) -> u32 {
    match try_uprobe_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_uprobe_test(ctx: ProbeContext) -> Result<u32, i64> {
    let arg0: *const u8  = ctx.arg(0).ok_or(0u32)?;
    let mut buf = [0u8; 128];
    let filename = unsafe {
        let filename_bytes = bpf_probe_read_user_str_bytes(arg0, &mut buf)?;
        from_utf8_unchecked(filename_bytes)
    };
    info!(&ctx, "function execve called by libc {}", filename);
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
