#![no_std]
#![no_main]

mod maps;
mod helpers;
mod display;
mod filter;
mod hook_enter;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
