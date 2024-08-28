#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, programs::XdpContext};
use aya_log_ebpf::info;
use aya_ebpf::maps::array::Array;

mod config;
mod check;

use check::check_config;
use config::Config;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, tcp::TcpHdr, udp::UdpHdr};

#[map]
static BLACKLIST: Array<Config> = Array::with_max_entries(128,0);

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

#[xdp]
pub fn adv_firewall(ctx: XdpContext) -> u32 {
    match try_adv_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_adv_firewall(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "Received a packet");
    let ethhdr: *const EthHdr = ptr_at(&ctx,0)?;
    let src_addr: [u8;6] = unsafe { (*ethhdr).src_addr };
    let dst_addr: [u8;6] = unsafe { (*ethhdr).dst_addr };
    let ether : EtherType = unsafe { (*ethhdr).ether_type };
    let mut src_ip: u32 = 0;
    let mut protocoll: IpProto = IpProto::Tcp;
    let mut dst_port: u16 = 0;
    match ether
    {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            src_ip = unsafe { (*ipv4hdr).src_addr };
            let dst_ip = unsafe { (*ipv4hdr).dst_addr };
            protocoll = unsafe { (*ipv4hdr).proto };
            let protocol = protocoll as u8;
            match protocol
            {
                6 => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN+Ipv4Hdr::LEN)?;
                    let src_port = unsafe { (*tcphdr).source };
                    dst_port = unsafe { (*tcphdr).dest };
                    let cnfg = Config::new(Some(src_addr), Some(dst_addr), Some(ether as u16), Some(src_ip), Some(dst_ip), Some(protocol), Some(src_port), Some(dst_port));
                    if check_config(&ctx, &cnfg)
                    {
                        return Ok(xdp_action::XDP_DROP);
                    }
                    
                },
                17 => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN+Ipv4Hdr::LEN)?;
                    let src_port = unsafe { (*udphdr).source };
                    dst_port = unsafe { (*udphdr).dest };
                    let cnfg = Config::new(Some(src_addr), Some(dst_addr), Some(ether as u16), Some(src_ip), Some(dst_ip), Some(protocol), Some(src_port), Some(dst_port));
                    if check_config(&ctx, &cnfg)
                    {
                        return Ok(xdp_action::XDP_DROP);
                    }
                },
                1 =>
                {
                    let cnfg = Config::new(Some(src_addr), Some(dst_addr), Some(ether as u16), Some(src_ip), Some(dst_ip), Some(protocol), Some(0), Some(0));
                    if check_config(&ctx, &cnfg)
                    {
                        return Ok(xdp_action::XDP_DROP);
                    }

                },
                _ => {
                    info!(&ctx, "Packet dropped due to unsupported protocol");
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        },
        EtherType::Ipv6 => {
            protocoll = IpProto::Ipv6;
        },
        EtherType::Arp => {
            protocoll = IpProto::Narp;
        },
        _ => {
            info!(&ctx, "Packet dropped due to unsupported ether type");
            return Ok(xdp_action::XDP_DROP);
        }
    }
    let protocoll = match protocoll
    {
        IpProto::Tcp => "TCP",
        IpProto::Udp => "UDP",
        IpProto::Icmp => "ICMP",
        _ => "Unknown",
    };
    info!(&ctx, "{} packet from {} to dest port {} is allowed", protocoll, src_ip, dst_port);
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/*
None-None-None-10.0.3.3-10.0.4.3-UDP-None-None
*/