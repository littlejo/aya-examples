use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes, macros::tracepoint, programs::TracePointContext,
};

use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use aya_log_ebpf::debug;

use crate::common::*;

const FILENAME_OFFSET: usize = 16;
const INIT_STATE: ProgramState = ProgramState {
    t_enter: 0,
    t_exit: 0,
    buffer: ZEROED_ARRAY,
    ret: 0,
};

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    let t = unsafe { bpf_ktime_get_ns() };
    debug!(&ctx, "main {}", t);
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    PROGRAM.insert(&tgid, &INIT_STATE, 0)?;
    let program_state = unsafe { &mut *PROGRAM.get_ptr_mut(&tgid).ok_or(0)? };
    program_state.t_enter = t;
    unsafe {
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        bpf_probe_read_user_str_bytes(filename_src_addr, &mut program_state.buffer)?;
    };
    Ok(0)
}
