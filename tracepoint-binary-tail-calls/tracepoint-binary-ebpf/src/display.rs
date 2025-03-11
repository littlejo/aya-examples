use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::{debug, info};
use core::str::from_utf8_unchecked;

use crate::common::*;

#[tracepoint]
pub fn tracepoint_binary_display(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_display(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_display(ctx: TracePointContext) -> Result<u32, i64> {
    debug!(&ctx, "display");
    let buf = BUF.get(0).ok_or(0)?;
    let cmd = &buf[..];
    let filename = unsafe { from_utf8_unchecked(cmd) };
    info!(
        &ctx,
        "tracepoint sys_enter_execve called. Binary: {}", filename
    );
    Ok(0)
}
