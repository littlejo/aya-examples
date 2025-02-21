#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuHashMap},
    programs::TracePointContext,
};

use tracepoint_binary_common::MAX_PATH_LEN;

use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::maps::ProgramArray;
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use aya_log_ebpf::{debug, error, info};

use core::str::from_utf8_unchecked;

const FILENAME_OFFSET: usize = 16;
const DEFAULT_KEY: u8 = 0;
const ZEROED_ARRAY: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[repr(C)]
struct ProgramState {
    timestamp: u64,
    duration: u64,
    ret: i64,
}

#[map]
static BUF: PerCpuHashMap<u8, [u8; MAX_PATH_LEN]> = PerCpuHashMap::with_max_entries(1, 0);

#[map]
static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);

#[map]
static PROGRAM: PerCpuArray<ProgramState> = PerCpuArray::with_max_entries(1, 0);

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[inline(always)]
fn get_program_state() -> Result<&'static mut ProgramState, i64> {
    unsafe {
        let ptr = PROGRAM.get_ptr_mut(0).ok_or(0)?;
        Ok(&mut *ptr)
    }
}

#[inline(always)]
fn read_exit_code(ctx: &TracePointContext) -> Result<i64, i64> {
    unsafe { ctx.read_at(16) }
}

#[inline(always)]
fn get_timestamp() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

#[inline(always)]
fn try_tail_call(ctx: &TracePointContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "exit: tail_call failed");
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
    let t = get_timestamp();
    debug!(&ctx, "main {}", t);

    let program_state = get_program_state()?;
    program_state.timestamp = t;

    BUF.insert(&DEFAULT_KEY, &ZEROED_ARRAY, 0)?;
    let buf = BUF.get_ptr_mut(&DEFAULT_KEY).ok_or(0)?;
    unsafe {
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?;
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
    debug!(&ctx, "filter");
    let is_excluded = unsafe {
        let buf = BUF.get(&DEFAULT_KEY).ok_or(0)?;
        EXCLUDED_CMDS.get(buf).is_some()
    };
    let program_state = get_program_state()?;

    if program_state.ret != 0 || is_excluded {
        info!(&ctx, "No log for this Binary, ret: {}", program_state.ret);
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
    let filename = unsafe {
        let cmd = &BUF.get(&DEFAULT_KEY).ok_or(0)?[..];
        from_utf8_unchecked(cmd)
    };
    let program_state = get_program_state()?;
    info!(
        &ctx,
        "tracepoint execve called. Binary: {}, duration: {} ns", filename, program_state.duration
    );
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
    let t = get_timestamp();
    let program_state = get_program_state()?;
    program_state.duration = t - program_state.timestamp;
    program_state.ret = read_exit_code(&ctx)?;
    debug!(&ctx, "exit {}", program_state.ret);
    try_tail_call(&ctx, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
