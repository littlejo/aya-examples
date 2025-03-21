#![no_std]
#![no_main]

mod common;
mod display;
mod filter;
mod hook;
mod hook_exit;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
