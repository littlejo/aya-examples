#![no_std]
#![no_main]

mod helpers;
mod maps;

mod hook_enter;
mod filter;
mod display;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
