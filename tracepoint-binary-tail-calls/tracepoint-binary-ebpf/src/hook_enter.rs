use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    helpers::bpf_probe_read_user_str_bytes,
};

use crate::maps::*;
use crate::helpers::*;

use aya_log_ebpf::debug;

use tracepoint_binary_common::MAX_PATH_LEN;

const FILENAME_OFFSET: usize = 16;
const ZEROED_ARRAY: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    debug!(&ctx, "main");
    let buf = BUF.get_ptr_mut(0).ok_or(0)?;

    unsafe {
        *buf = ZEROED_ARRAY;
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?;
    };

    try_tail_call(&ctx, 0);

    Ok(0)
}
