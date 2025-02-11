#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::{PerCpuArray, HashMap, ProgramArray},
    programs::TracePointContext,
    helpers::bpf_probe_read_user_str_bytes,
    helpers::gen::bpf_get_smp_processor_id,
};
use aya_log_ebpf::{info,error,debug};

use core::str::from_utf8_unchecked;

use tracepoint_binary_common::MAX_PATH_LEN;

const FILENAME_OFFSET: usize = 16;

#[map]
static EXCLUDED_CMDS: HashMap<[u8; MAX_PATH_LEN], u8> = HashMap::with_max_entries(10, 0);

#[map]
static BUF: PerCpuArray<[u8; MAX_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    let cpu_id = unsafe { bpf_get_smp_processor_id() };
    debug!(&ctx, "main {}", cpu_id as u32);
    let _filename = unsafe {
        let buf = BUF.get_ptr_mut(0).ok_or(0)?;
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?;
        from_utf8_unchecked(filename_bytes)
    };

    let res = unsafe { JUMP_TABLE.tail_call(&ctx, 0) };
    if res.is_err() {
        error!(&ctx, "main: tail_call failed");
    }
    Ok(0)
}

#[tracepoint]
pub fn tracepoint_binary_filter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_filter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_filter(ctx: TracePointContext) -> Result<u32, i64> {
    let cpu_id = unsafe { bpf_get_smp_processor_id() };
    debug!(&ctx, "filter {}", cpu_id as u32);
    let _filename = unsafe {
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

    let res = unsafe { JUMP_TABLE.tail_call(&ctx, 1) };
    if res.is_err() {
        error!(&ctx, "filter: tail_call failed");
    }
    Ok(0)
}

#[tracepoint]
pub fn tracepoint_binary_display(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_display(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_display(ctx: TracePointContext) -> Result<u32, i64> {
    let cpu_id = unsafe { bpf_get_smp_processor_id() };
    debug!(&ctx, "display {}", cpu_id as u32);
    let filename = unsafe {
        let buf = BUF.get_ptr_mut(0).ok_or(0)?;
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?;
        from_utf8_unchecked(filename_bytes)
    };

    info!(&ctx, "tracepoint sys_enter_execve called. Binary: {}", filename);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
