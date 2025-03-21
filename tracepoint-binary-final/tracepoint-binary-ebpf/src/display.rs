use aya_ebpf::helpers::bpf_get_current_pid_tgid;
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
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let program = unsafe { PROGRAM.get(&tgid).ok_or(0)? };
    let cmd = &program.buffer[..];
    let filename = unsafe { from_utf8_unchecked(cmd) };
    let duration = program.t_exit - program.t_enter;

    info!(
        &ctx,
        "tracepoint sys_*_execve called. Binary: {}, Duration: {}ns", filename, duration
    );
    Ok(0)
}
