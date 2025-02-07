#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    helpers::bpf_probe_read_user_str_bytes,
};
use aya_log_ebpf::info;

use core::str::from_utf8_unchecked;

const LEN_MAX_PATH: usize = 16;
const FILENAME_OFFSET: usize = 16;

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    let mut buf = [0u8; LEN_MAX_PATH];

    let filename = unsafe {
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_src_addr, &mut buf)?;
        from_utf8_unchecked(filename_bytes)
    };

    info!(&ctx, "tracepoint sys_enter_execve called. Binary: {}", filename);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
