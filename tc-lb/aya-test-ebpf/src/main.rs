#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_ebpf::bindings::TC_ACT_SHOT;
use aya_ebpf::bindings::BPF_F_PSEUDO_HDR;
use aya_log_ebpf::info;


use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[classifier]
pub fn aya_test(ctx: TcContext) -> i32 {
    match try_aya_test(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_aya_test(mut ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let mut udphdr: UdpHdr;
    let offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let old_port = match ipv4hdr.proto {
        IpProto::Udp => {
            udphdr = ctx.load(offset).map_err(|_| ())?;
            u16::from_be_bytes(udphdr.dest)
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let destination = u32::from_be_bytes(ipv4hdr.dst_addr);
    let new_port: u16 = 8080;
    let new_port_be = new_port.to_be_bytes();
    udphdr.dest = new_port_be;
    ctx.store(offset, &udphdr, 0).map_err(|_| ())?;
    info!(&ctx, "DEST {:i} {}", destination, old_port);
    ctx.l4_csum_replace(
        offset + 6,
        old_port as u64,
        new_port as u64,
        0x2 | BPF_F_PSEUDO_HDR as u64,
    ).map_err(|_| ())?;
    info!(&ctx, "Checksum replacement done.");

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
