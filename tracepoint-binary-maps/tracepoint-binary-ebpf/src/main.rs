#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    programs::TracePointContext,
    helpers::bpf_probe_read_user_str_bytes,
    helpers::bpf_get_current_pid_tgid,
    maps::HashMap,
};

use aya_ebpf::maps::ProgramArray;
use aya_ebpf::maps::LruHashMap;

use tracepoint_binary_common::MAX_PATH_LEN;

use aya_log_ebpf::{debug,info,error};

use core::str::from_utf8_unchecked;

use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

const FILENAME_OFFSET: usize = 16;

#[repr(C)]
struct ProgramState {
    t_enter: u64,
    t_exit: u64,
    buffer: [u8; MAX_PATH_LEN],
}

const INIT_STATE: ProgramState = ProgramState {
    t_enter: 0,
    t_exit: 0,
    buffer: [0; MAX_PATH_LEN],
};

#[map]
static PROGRAM: LruHashMap<u32, ProgramState> = LruHashMap::with_max_entries(16, 0);

#[map]
static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);

#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

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
    let t = unsafe{ bpf_ktime_get_ns() };
    debug!(&ctx, "main {}", t);
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    PROGRAM.insert(&tgid, &INIT_STATE, 0)?;

    let program = PROGRAM.get_ptr_mut(&tgid).ok_or(0)?;

    unsafe {
        let program_state = &mut *program;
        program_state.t_enter = t;
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        bpf_probe_read_user_str_bytes(filename_src_addr, &mut program_state.buffer)?;
    };
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
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let program = unsafe { PROGRAM.get(&tgid).ok_or(0)? };

    let is_excluded = unsafe {
        EXCLUDED_CMDS.get(&program.buffer).is_some()
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
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let program = unsafe { PROGRAM.get(&tgid).ok_or(0)? };
    let cmd = &program.buffer[..];
    let t_exit = program.t_exit;
    let t_enter = program.t_enter;
    let duration = t_exit - t_enter;
    let filename = unsafe { from_utf8_unchecked(cmd) };

    info!(&ctx, "tracepoint sys_enter_execve called. Binary: {}, duration: {}", filename, duration);
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
    let t_exit = unsafe{ bpf_ktime_get_ns() };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let p = PROGRAM.get_ptr_mut(&tgid).ok_or(0)?;
    unsafe {
        let program_state = &mut *p;
        program_state.t_exit = t_exit;
    }
    debug!(&ctx, "exit {}", t_exit);
    try_tail_call(&ctx, 0);
    Ok(0)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
