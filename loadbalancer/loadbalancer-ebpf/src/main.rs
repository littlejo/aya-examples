#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use loadbalancer_common::BackendPorts;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use core::mem;

#[map(name = "BACKEND_PORTS")]
static mut BACKEND_PORTS: HashMap<u16, BackendPorts> =
    HashMap::<u16, BackendPorts>::with_max_entries(10, 0);

#[xdp]
pub fn loadbalancer(ctx: XdpContext) -> u32 {
    match try_loadbalancer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_loadbalancer(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let udphdr: *mut UdpHdr;
    let destination_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {
            udphdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };
    if destination_port != 9875 {
        return Ok(xdp_action::XDP_PASS);
    }
    info!(&ctx, "received a {} UDP packet", destination_port);
    let backends = match unsafe { BACKEND_PORTS.get(&destination_port) } {
        Some(backends) => {
            info!(&ctx, "FOUND backends for port");
            backends
        }
        None => {
            info!(&ctx, "NO backends found for this port");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if backends.index > backends.ports.len() - 1 {
        return Ok(xdp_action::XDP_ABORTED);
    }

    let new_destination_port = backends.ports[backends.index];

    unsafe { (*udphdr).dest = u16::to_be(new_destination_port) };

    info!(
        &ctx,
        "redirected port {} to {}", destination_port, new_destination_port
    );

    let mut new_backends = BackendPorts {
        ports: backends.ports,
        index: backends.index + 1,
    };

    if new_backends.index > new_backends.ports.len() - 1
        || new_backends.ports[new_backends.index] == 0
    {
        new_backends.index = 0;
    }

    match unsafe { BACKEND_PORTS.insert(&destination_port, &new_backends, 0) } {
        Ok(_) => {
            info!(&ctx, "index updated for port {}", destination_port);
            Ok(xdp_action::XDP_PASS)
        }
        Err(err) => {
            info!(&ctx, "error inserting index update: {}", err);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
