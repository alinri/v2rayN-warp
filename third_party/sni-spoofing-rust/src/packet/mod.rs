pub mod eth;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod tls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Ethernet,
    NullLoopback,
    RawIp,
}

impl FrameKind {
    pub fn link_header_len(self) -> usize {
        match self {
            FrameKind::Ethernet => eth::ETH_HEADER_LEN,
            FrameKind::NullLoopback => 4,
            FrameKind::RawIp => 0,
        }
    }
}

pub fn detect_ip_version(data: &[u8], kind: FrameKind) -> Option<IpVersion> {
    match kind {
        FrameKind::Ethernet => eth::ethertype(data),
        FrameKind::NullLoopback => {
            if data.len() < 5 {
                return None;
            }
            match data[4] >> 4 {
                4 => Some(IpVersion::V4),
                6 => Some(IpVersion::V6),
                _ => None,
            }
        }
        FrameKind::RawIp => {
            if data.is_empty() {
                return None;
            }
            match data[0] >> 4 {
                4 => Some(IpVersion::V4),
                6 => Some(IpVersion::V6),
                _ => None,
            }
        }
    }
}
