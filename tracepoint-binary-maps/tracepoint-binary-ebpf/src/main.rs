#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    programs::TracePointContext,
    helpers::bpf_probe_read_user_str_bytes,
    maps::{PerCpuArray, HashMap},
};

use aya_ebpf::maps::ProgramArray;

use tracepoint_binary_common::MAX_PATH_LEN;

use aya_log_ebpf::{debug,info,error};

use core::str::from_utf8_unchecked;

use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

const FILENAME_OFFSET: usize = 16;
const ZEROED_ARRAY: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[repr(C)]
struct ProgramState {
    timestamp: u64,
    buffer: [u8; MAX_PATH_LEN],
}

#[map]
static PROGRAM: PerCpuArray<ProgramState> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[inline(always)]
fn try_tail_call(ctx: &TracePointContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "filter: tail_call failed");
    }
}

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    let t = unsafe{ bpf_ktime_get_ns() };
    debug!(&ctx, "main {}", t);
    let program = PROGRAM.get_ptr_mut(0).ok_or(0)?;

    unsafe {
        let program_state = &mut *program;
        program_state.buffer = ZEROED_ARRAY;
        program_state.timestamp = t;
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        bpf_probe_read_user_str_bytes(filename_src_addr, &mut program_state.buffer)?;
    }

    try_tail_call(&ctx, 0);
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
    debug!(&ctx, "filter");
    let buf = &PROGRAM.get(0).ok_or(0)?.buffer;

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

#[tracepoint]
pub fn tracepoint_binary_display(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_display(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_display(ctx: TracePointContext) -> Result<u32, i64> {
    debug!(&ctx, "display");
    let cmd = &PROGRAM.get(0).ok_or(0)?.buffer[..];
    let filename = unsafe { from_utf8_unchecked(cmd) };

    info!(&ctx, "tracepoint sys_enter_execve called. Binary: {}", filename);
    Ok(0)
}

#[tracepoint]
pub fn tracepoint_binary_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let t = unsafe{ bpf_ktime_get_ns() };
    let timestamp = PROGRAM.get(0).ok_or(0)?.timestamp;
    debug!(&ctx, "exit {}", t);
    info!(&ctx, "tracepoint sys_exit_execve called, duration : {}", t - timestamp);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
