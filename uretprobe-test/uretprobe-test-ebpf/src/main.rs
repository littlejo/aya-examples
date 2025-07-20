#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_ebpf::{macros::uretprobe, programs::RetProbeContext};
use aya_log_ebpf::info;

use aya_ebpf::{macros::map, maps::LruHashMap};

use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

#[map]
pub static T_ENTER: LruHashMap<u32, u64> = LruHashMap::with_max_entries(16, 0);

#[uprobe]
pub fn uprobe_test(ctx: ProbeContext) -> u32 {
    match try_uprobe_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_uprobe_test(ctx: ProbeContext) -> Result<u32, i64> {
    let t = unsafe { bpf_ktime_get_ns() };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    T_ENTER.insert(&tgid, &t, 0)?;
    info!(
        &ctx,
        "{} - function main.CheckPassword called by /home/cloud_user/go/auth/main entry", t
    );
    Ok(0)
}

#[uretprobe]
pub fn uretprobe_test(ctx: RetProbeContext) -> u32 {
    match try_uretprobe_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_uretprobe_test(ctx: RetProbeContext) -> Result<u32, i32> {
    let t = unsafe { bpf_ktime_get_ns() };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let t_enter = unsafe { T_ENTER.get(&tgid).ok_or(0)? };
    let retval: u8 = ctx.ret().ok_or(1i32)?;
    info!(
        &ctx,
        " {} - function main.CheckPassword called by /home/cloud_user/go/auth/main {}, duration: {}",
        t,
        retval,
        t - t_enter
    );
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
