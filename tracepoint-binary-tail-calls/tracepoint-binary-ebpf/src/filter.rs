use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

use aya_log_ebpf::{debug,info};
use crate::maps::*;
use crate::helpers::*;

#[tracepoint]
pub fn tracepoint_binary_filter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_filter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_filter(ctx: TracePointContext) -> Result<u32, i64> {
    debug!(&ctx, "filter");
    let buf = BUF.get(0).ok_or(0)?;

    let is_excluded = unsafe {
        EXCLUDED_CMDS.get(buf).is_some()
    };

    if is_excluded {
        info!(&ctx, "No log for this Binary");
        return Ok(0);
    }

    try_tail_call(&ctx, 1);

    Ok(0)
}
