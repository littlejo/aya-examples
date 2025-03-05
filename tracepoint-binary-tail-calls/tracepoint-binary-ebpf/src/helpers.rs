use aya_ebpf::programs::TracePointContext;

use crate::maps::*;
use aya_log_ebpf::error;

#[inline(always)]
pub fn try_tail_call(ctx: &TracePointContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "exit: tail_call failed");
    }
}
