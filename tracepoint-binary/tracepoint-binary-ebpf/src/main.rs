#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::{PerCpuArray, HashMap},
    programs::TracePointContext,
    helpers::bpf_probe_read_user_str_bytes,
};
use aya_log_ebpf::info;

use core::str::from_utf8_unchecked;

use tracepoint_binary_common::MAX_PATH_LEN;

const FILENAME_OFFSET: usize = 16;

#[map]
static EXCLUDED_CMDS: HashMap<[u8; MAX_PATH_LEN], u8> = HashMap::with_max_entries(10, 0);

#[map]
static BUF: PerCpuArray<[u8; MAX_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    let filename = unsafe {
        let buf = BUF.get_ptr_mut(0).ok_or(0)?;
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?;
        from_utf8_unchecked(filename_bytes)
    };

    let is_excluded = unsafe {
        let buf = BUF.get(0).ok_or(0)?;
        EXCLUDED_CMDS.get(buf).is_some()
    };

    if is_excluded {
        info!(&ctx, "No log for this Binary");
        return Ok(0);
    }

    info!(&ctx, "tracepoint sys_enter_execve called. Binary: {}", filename);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
