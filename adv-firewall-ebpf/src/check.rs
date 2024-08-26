use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use crate::{config::Config, BLACKLIST};

pub fn check_config(
    ctx: &XdpContext,
    config: &Config
) -> bool
{

    let src_addr: [u8;6] = config.src_mac.unwrap();
    let dst_addr: [u8;6] = config.dst_mac.unwrap();
    let ether: u16 = config.ether_type.unwrap();
    let src_ip: u32 = config.src_ip.unwrap();
    let dst_ip: u32 = config.dst_ip.unwrap();
    let protocol: u8 = config.protocol.unwrap();
    let src_port: u16 = config.src_port.unwrap();
    let dst_port: u16 = config.dst_port.unwrap();
    for i in 0..128
    {
        if let Some(entry) = BLACKLIST.get(i)
        {
            info!(ctx, "Checking entry {}", i);
            let mut flag = false;
            if let Some(src_macc) = entry.src_mac
            {
                if src_macc != src_addr
                {
                    continue;
                }
                else {
                    info!(ctx, "src_mac matched");
                    flag = true;
                }
            }
            if let Some(dst_macc) = entry.dst_mac
            {
                if dst_macc != dst_addr
                {
                    continue;
                }
                else {
                    info!(ctx, "dst_mac matched");
                    flag = true;
                }
            }
            if let Some(ether_type) = entry.ether_type
            {
                if ether_type != ether
                {
                    continue;
                }
                else {
                    info!(ctx, "ether_type matched");
                    flag = true;
                }
            }
            if let Some(src_ipp) = entry.src_ip
            {
                if src_ipp != src_ip
                {
                    continue;
                }
                else {
                    info!(ctx, "src_ip matched");
                    flag = true;
                }
            }
            if let Some(dst_ipp) = entry.dst_ip
            {
                if dst_ipp != dst_ip
                {
                    continue;
                }
                else {
                    info!(ctx, "dst_ip matched");
                    flag = true;
                }
            }
            if let Some(protocoll) = entry.protocol
            {
                if protocoll != protocol
                {
                    continue;
                }
                else {
                    info!(ctx, "protocol matched");
                    flag = true;
                }
            }
            if let Some(src_portt) = entry.src_port
            {
                if src_portt != src_port
                {
                    continue;
                }
                else {
                    info!(ctx, "src_port matched");
                    flag = true;
                }
            }
            if let Some(dst_portt) = entry.dst_port
            {
                if dst_portt != dst_port
                {
                    continue;
                }
                else {
                    info!(ctx, "dst_port matched");
                    flag = true;
                }
            }
            if flag == true
            {
                info!(ctx, "{} packet from {} to dest port {} is dropped",protocol,src_ip,dst_port);
                return true;
            }
        }
        else {
            break;
        }
    }
    false    
}