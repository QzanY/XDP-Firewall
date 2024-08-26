use anyhow::Context;
use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::signal;

mod config;
use config::Config;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp0s10")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/adv-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/adv-firewall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("adv_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // let mut counter = 0;
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    info!("Listening for incoming IP addresses on localhost:8080...");
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            Ok((socket, _)) = listener.accept() => {
                let mut reader = BufReader::new(socket);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok() {
                    //Input format : ADD-1-None-None-ipv4-10.0.3.3-None-TCP-None-None
                    let mut parts = line.trim().split("-");
                    let command = parts.next().unwrap().trim();
                    if command == "DEL" {
                        let index = parts.next().unwrap().trim();
                        let cnfg = Config::default();
                        let mut blacklist: Array<_,Config>= Array::try_from(bpf.map_mut("BLACKLIST").unwrap())?;
                        blacklist.set(index.parse().unwrap(),cnfg,0)?;
                        info!("Deleted rule from blacklist");
                    }
                    else if command == "ADD"
                    {
                        let index = parts.next().unwrap().trim();
                        let src_mac = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => {
                                    let mut mac = [0;6];
                                    let parts: Vec<&str> = part.trim().split(":").collect();
                                    for (i, part) in parts.iter().enumerate() {
                                        mac[i] = u8::from_str_radix(part, 16).unwrap();
                                    }
                                    Some(mac)
                                }
                            }
                        };
                        let dst_mac = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => {
                                    let mut mac = [0;6];
                                    let parts: Vec<&str> = part.trim().split(":").collect();
                                    for (i, part) in parts.iter().enumerate() {
                                        mac[i] = u8::from_str_radix(part, 16).unwrap();
                                    }
                                    Some(mac)
                                }
                            }
                        };
                        let ether_type = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => {
                                    let ether_type = match part
                                    {
                                        "ipv4" => 0x0800,
                                        "ipv6" => 0x86DD,
                                        _ => 0,
                                    };
                                    Some(ether_type)
                                }
                            }
                        };
                        let src_ip = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => {
                                    let parts: Vec<&str> = part.trim().split(".").collect();
                                    let mut ip = [0; 4];
                                    for (i, part) in parts.iter().enumerate() {
                                        ip[i] = u8::from_str_radix(part, 10).unwrap();
                                    }
                                    Some(u32::from_be_bytes(ip))
                                }
                            }
                        };
                        let dst_ip = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => {
                                    let parts: Vec<&str> = part.trim().split(".").collect();
                                    let mut ip = [0; 4];
                                    for (i, part) in parts.iter().enumerate() {
                                        ip[i] = u8::from_str_radix(part, 10).unwrap();
                                    }
                                    Some(u32::from_be_bytes(ip))
                                }
                            }
                        };
                        let protocol = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => {
                                    let proto = match part
                                    {
                                        "TCP" => 6,
                                        "UDP" => 17,
                                        "ICMP" => 1,
                                        _ => 0,
                                    };
                                    Some(proto)
                                }
                            }
                        };
                        let src_port = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => Some(u16::from_str_radix(part, 10).unwrap())
                            }
                        };
                        let dst_port = {
                            let part : &str = parts.next().unwrap().trim();
                            match part
                            {
                                "None" => None,
                                _ => Some(u16::from_str_radix(part, 10).unwrap())
                            }
                        };
                        let config = Config::new(src_mac, dst_mac, ether_type, src_ip, dst_ip, protocol, src_port, dst_port);

                        let mut blacklist: Array<_,Config>= Array::try_from(bpf.map_mut("BLACKLIST").unwrap())?;
                        blacklist.set(index.parse().unwrap(),&config,0)?;
                        info!("Added new rule to blacklist");
                    }
                    else
                    {
                        info!("Invalid command");
                    }
                }
            }
        }
    }
    Ok(())
}
