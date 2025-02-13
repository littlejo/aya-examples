#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    macros::map,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use aya_ebpf::helpers::bpf_get_current_uid_gid;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

use aya_ebpf::maps::hash_map::LruHashMap;
use aya_ebpf::maps::hash_map::PerCpuHashMap;

use core::str::from_utf8_unchecked;

#[map]
static TIMESTAMP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(10, 0);

#[map]
static CMD: LruHashMap<u32, [u8; 512]> = LruHashMap::with_max_entries(10, 0);

#[map]
static BUF: PerCpuHashMap<u8, [u8; 512]> = PerCpuHashMap::with_max_entries(1, 0);

#[tracepoint]
pub fn multi(ctx: TracePointContext) -> u32 {
    match try_multi(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_multi(ctx: TracePointContext) -> Result<u32, i64> {
    let uid = bpf_get_current_uid_gid() as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    let ret :i64 = unsafe { ctx.read_at(16)? };
    let timestamp = unsafe { bpf_ktime_get_ns() };
    let enter_timestamp = *unsafe { TIMESTAMP.get(&pid).ok_or(0)? };
    let duration = timestamp - enter_timestamp;

    //let buf = unsafe { BUF.get(&0).ok_or(0)? };
    //let buf_copy = *buf;
    //let buf_str = unsafe { from_utf8_unchecked(&buf_copy) };

    //let buf = unsafe { &BUF.get(&0).ok_or(0)?[..] };
    //let buf_str = unsafe { from_utf8_unchecked(buf) };
    
    //let buf_str = unsafe {
    //    let buf = &BUF.get(&0).ok_or(0)?[..];
    //    from_utf8_unchecked(buf) 
    //};

    let cmd_str = unsafe {
        let cmd = &CMD.get(&pid).ok_or(0)?[..];
        from_utf8_unchecked(cmd) 
    };

    //let buf_str = unsafe { from_utf8_unchecked(&BUF.get(&0).ok_or(0)?[..]) };

    if ret == 0 {
    info!(&ctx, "tracepoint sys_exit_execve called {}, uid {}, pid {}, duration {}ns, binary: {}", ret, uid, pid, duration, cmd_str);
    } else {
    info!(&ctx, "problem: tracepoint sys_exit_execve called {}, uid {}, pid {}, duration {}ns, binary: {}", ret, uid, pid, duration, cmd_str);
    }
    Ok(0)
}

#[tracepoint]
pub fn multi_enter(ctx: TracePointContext) -> u32 {
    match try_multi_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_multi_enter(ctx: TracePointContext) -> Result<u32, i64> {
    //let uid = bpf_get_current_uid_gid() as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    let timestamp = unsafe { bpf_ktime_get_ns() };
    TIMESTAMP.insert(&pid, &timestamp, 0)?;
    CMD.insert(&pid, &[0u8; 512], 0)?;
    let cmd = CMD.get_ptr_mut(&pid).ok_or(0)?;
    //BUF.insert(&0, &[0u8; 512], 0)?;
    //let buf = BUF.get_ptr_mut(&0).ok_or(0)?;

    let ret_ptr :*const u8 = unsafe { ctx.read_at(16)? };
    unsafe { bpf_probe_read_user_str_bytes(ret_ptr, &mut *cmd)? };
    //let my_str_bytes = unsafe { bpf_probe_read_user_str_bytes(ret_ptr, &mut *cmd)? };
    //let ret_str = unsafe {core::str::from_utf8_unchecked(my_str_bytes)};
    //CMD.insert(&pid, &buf, 0);
    //info!(&ctx, "tracepoint sys_enter_execve called {}, uid {}, pid {}, timestamp {}", ret_str, uid, pid, timestamp);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
