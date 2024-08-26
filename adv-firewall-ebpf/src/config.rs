use core::fmt;

pub struct Config
{
    pub src_mac: Option<[u8;6]>,
    pub dst_mac: Option<[u8;6]>,
    pub ether_type: Option<u16>,
    pub src_ip: Option<u32>,
    pub dst_ip: Option<u32>,
    pub protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}


//Implement Display for Config
impl fmt::Display for Config
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "src_mac: {:?}, dst_mac: {:?}, ether_type: {:?}, src_ip: {:?}, dst_ip: {:?}, protocol: {:?}, src_port: {:?}, dst_port: {:?}", self.src_mac, self.dst_mac, self.ether_type, self.src_ip, self.dst_ip, self.protocol, self.src_port, self.dst_port)
    }
}

impl Config
{
    pub fn new(src_mac: Option<[u8;6]>, dst_mac: Option<[u8;6]>, ether_type: Option<u16>, src_ip: Option<u32>, dst_ip: Option<u32>, protocol: Option<u8>, src_port: Option<u16>, dst_port: Option<u16>) -> Config
    {
        Config
        {
            src_mac: src_mac,
            dst_mac: dst_mac,
            ether_type: ether_type,
            src_ip: src_ip,
            dst_ip: dst_ip,
            protocol: protocol,
            src_port: src_port,
            dst_port: dst_port,
        }
    }
}