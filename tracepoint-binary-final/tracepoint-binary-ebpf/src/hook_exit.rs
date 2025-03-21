use aya_ebpf::{
    macros::tracepoint, programs::TracePointContext,
};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;

use aya_log_ebpf::debug;
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use crate::common::*;

#[tracepoint]
pub fn tracepoint_binary_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let t = unsafe{ bpf_ktime_get_ns() };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ret :i64 = unsafe { ctx.read_at(16)? };
    let program_state = unsafe { &mut *PROGRAM.get_ptr_mut(&tgid).ok_or(0)? };
    program_state.t_exit = t;
    program_state.ret = ret;
    debug!(&ctx, "exit {}", t);
    debug!(&ctx, "tracepoint sys_exit_execve called. ret: {}", ret);
    try_tail_call(&ctx, 0);
    Ok(0)
}
