// Thor Firewall - Universal Packet Parser
// يحلل حزم الشبكة من الطبقة 2 إلى الطبقة 4 بكفاءة فائقة

use std::convert::TryInto;

/// هيكل الحزمة المجردة (مستقل عن نظام التشغيل)
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub eth_type: EtherType,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub payload_len: usize,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpAddr {
    V4(u32),     // 32-bit IPv4
    V6([u8; 16]), // 128-bit IPv6
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// محلل الحزم الرئيسي (خالٍ من التخصيصات غير الضرورية)
pub struct PacketParser;

impl PacketParser {
    /// يحلل حزمة خام من الذاكرة (مؤشر + طول)
    /// الإدخال: raw_packet - شريحة البايتات الخام
    /// الإخراج: ParsedPacket أو خطأ
    pub fn parse(raw_packet: &[u8]) -> Result<ParsedPacket, &'static str> {
        if raw_packet.len() < 14 {
            return Err("Packet too short for Ethernet header");
        }

        // قراءة عناوين MAC (بايت 0-5: dst, 6-11: src)
        let dst_mac = raw_packet[0..6].try_into().unwrap();
        let src_mac = raw_packet[6..12].try_into().unwrap();

        // نوع الإيثرنت (بايت 12-13)
        let eth_type_u16 = u16::from_be_bytes([raw_packet[12], raw_packet[13]]);
        let eth_type = match eth_type_u16 {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            _ => EtherType::Unknown(eth_type_u16),
        };

        match eth_type {
            EtherType::Ipv4 => Self::parse_ipv4(&raw_packet[14..], src_mac, dst_mac, eth_type),
            EtherType::Ipv6 => Self::parse_ipv6(&raw_packet[14..], src_mac, dst_mac, eth_type),
            EtherType::Arp => Ok(ParsedPacket {
                src_mac,
                dst_mac,
                eth_type,
                src_ip: IpAddr::V4(0),
                dst_ip: IpAddr::V4(0),
                protocol: IpProtocol::Other(0),
                src_port: None,
                dst_port: None,
                payload_len: 0,
                timestamp_ns: Self::get_time_ns(),
            }),
            EtherType::Unknown(_) => Err("Unsupported EtherType"),
        }
    }

    fn parse_ipv4(data: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6], eth_type: EtherType) -> Result<ParsedPacket, &'static str> {
        if data.len() < 20 {
            return Err("IPv4 header too short");
        }
        let version_ihl = data[0];
        let ihl = (version_ihl & 0x0F) * 4; // طول الرأس بالبايت
        if data.len() < ihl as usize {
            return Err("IPv4 packet truncated");
        }
        let protocol = match data[9] {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            1 => IpProtocol::Icmp,
            other => IpProtocol::Other(other),
        };
        let src_ip = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let dst_ip = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let (src_port, dst_port, payload_len) = if data.len() >= ihl as usize + 4 {
            match protocol {
                IpProtocol::Tcp | IpProtocol::Udp => {
                    let src_port = u16::from_be_bytes([data[ihl as usize], data[ihl as usize + 1]]);
                    let dst_port = u16::from_be_bytes([data[ihl as usize + 2], data[ihl as usize + 3]]);
                    (Some(src_port), Some(dst_port), data.len() - ihl as usize - 4)
                }
                _ => (None, None, data.len() - ihl as usize),
            }
        } else {
            (None, None, 0)
        };
        Ok(ParsedPacket {
            src_mac,
            dst_mac,
            eth_type,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            protocol,
            src_port,
            dst_port,
            payload_len,
            timestamp_ns: Self::get_time_ns(),
        })
    }

    // دالة مبسطة لـ IPv6 (يمكن توسيعها لاحقًا)
    fn parse_ipv6(data: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6], eth_type: EtherType) -> Result<ParsedPacket, &'static str> {
        if data.len() < 40 {
            return Err("IPv6 header too short");
        }
        let next_header = data[6];
        let protocol = match next_header {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmp,
            other => IpProtocol::Other(other),
        };
        let mut src_ip = [0u8; 16];
        src_ip.copy_from_slice(&data[8..24]);
        let mut dst_ip = [0u8; 16];
        dst_ip.copy_from_slice(&data[24..40]);
        // تبسيط: نهمل منافذ TCP/UDP هنا (يمكن إضافتها)
        Ok(ParsedPacket {
            src_mac,
            dst_mac,
            eth_type,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            protocol,
            src_port: None,
            dst_port: None,
            payload_len: data.len() - 40,
            timestamp_ns: Self::get_time_ns(),
        })
    }

    #[cfg(target_os = "linux")]
    fn get_time_ns() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    #[cfg(target_os = "windows")]
    fn get_time_ns() -> u64 {
        // Windows: استخدام QueryPerformanceCounter
        use winapi::um::profileapi::QueryPerformanceCounter;
        let mut counter: u64 = 0;
        unsafe { QueryPerformanceCounter(&mut counter as *mut _ as *mut _) };
        counter // بشكل مبسط، قد نحتاج للتحويل إلى ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_tcp() {
        // حزمة IPv4 + TCP بسيطة (مثال)
        let raw = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst_mac
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // src_mac
            0x08, 0x00, // EtherType IPv4
            0x45, 0x00, 0x00, 0x28, // IPv4 header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, // protocol=6 (TCP)
            0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02, // 192.168.1.2
            0x00, 0x50, 0x00, 0x51, // src_port=80, dst_port=81
            0x00, 0x00, 0x00, 0x00, // payload dummy
        ];
        let pkt = PacketParser::parse(&raw).unwrap();
        assert_eq!(pkt.src_ip, IpAddr::V4(0xc0a80101));
        assert_eq!(pkt.dst_ip, IpAddr::V4(0xc0a80102));
        assert_eq!(pkt.protocol, IpProtocol::Tcp);
        assert_eq!(pkt.src_port, Some(80));
        assert_eq!(pkt.dst_port, Some(81));
    }
}
