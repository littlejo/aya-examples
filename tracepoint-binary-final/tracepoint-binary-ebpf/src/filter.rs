use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use aya_log_ebpf::debug;

use aya_ebpf::helpers::bpf_get_current_pid_tgid;

use crate::common::*;

#[tracepoint]
pub fn tracepoint_binary_filter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_filter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_filter(ctx: TracePointContext) -> Result<u32, i64> {
    debug!(&ctx, "filter");
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let program = unsafe { PROGRAM.get(&tgid).ok_or(0)? };

    let is_excluded = unsafe { EXCLUDED_CMDS.get(&program.buffer).is_some() };

    if is_excluded || program.ret != 0 {
        debug!(&ctx, "No log for this Binary");
        return Ok(0);
    }

    try_tail_call(&ctx, 1);

    Ok(0)
}
