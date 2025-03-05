#![no_std]
#![no_main]

mod maps;
mod helpers;
mod hook_enter;
mod filter;
mod display;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
