#![no_std]
#![no_main]


use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

use aya_ebpf::helpers::bpf_probe_read;

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
use crate::bindings::*;

#[tracepoint]
pub fn tracepoint_test2(ctx: TracePointContext) -> u32 {
    match try_tracepoint_test2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_test2(ctx: TracePointContext) -> Result<u32, i64> {
    let expires_t = unsafe {ctx.read_at::<u64>(24)?};
    let flags_t = unsafe {ctx.read_at::<u32>(40)?};
    let timer_ptr = unsafe {ctx.read_at::<* const timer_list>(8)?};
    let timer = unsafe { bpf_probe_read(timer_ptr)? };
    let expires = timer.expires;
    let flags = timer.flags;

    info!(&ctx, "tracepoint timer_start called expires={} flags={}, expires_t={}, flags_t={}", expires, flags, expires_t, flags_t);
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
