#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;
use aya_ebpf::EbpfContext;

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;

use core::str::from_utf8_unchecked;

#[tracepoint]
pub fn tracepoint_test3(ctx: TracePointContext) -> u32 {
    match try_tracepoint_test3(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_test3(ctx: TracePointContext) -> Result<u32, i64> {
    let name_data_loc = unsafe {ctx.read_at::<u32>(8)?};
    let offset = name_data_loc & 0xFFFF;
    let len = (name_data_loc >> 16) & 0xFFFF;
    info!(&ctx, "tracepoint netif_rx_entry called offset={} len={}", offset, len);

    let mut name_buf = [0u8; 16];
    let ptr_name = unsafe {ctx.as_ptr().add(offset as usize) as *const u8} ;
    let bytes_name = unsafe {bpf_probe_read_kernel_str_bytes(ptr_name, &mut name_buf)? };
    let name = unsafe { from_utf8_unchecked(bytes_name) };

    info!(&ctx, "tracepoint netif_rx_entry called {}", name);
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
