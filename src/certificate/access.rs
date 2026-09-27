use crate::Result;
use std::net::IpAddr;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix: u8,
}
impl Cidr {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or("CIDR requires a prefix")?;
        let address: IpAddr = address.parse()?;
        let prefix: u8 = prefix.parse()?;
        let aligned = match address {
            IpAddr::V4(ip) if prefix <= 32 => {
                u32::from(ip) & (u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)) == 0
            }
            IpAddr::V6(ip) if prefix <= 128 => {
                u128::from(ip) & (u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)) == 0
            }
            _ => false,
        };
        if !aligned {
            return Err("CIDR prefix is invalid or host bits are set".into());
        }
        Ok(Self { address, prefix })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Source(Cidr),
    Destination(Cidr),
    Service {
        category: String,
        permission: Permission,
        cidr: Cidr,
    },
}
impl Access {
    pub fn parse(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("urn:autobricks:")
            .ok_or("invalid policy namespace")?;
        let (category, value) = rest.split_once(':').ok_or("missing policy value")?;
        match category {
            "allowed-source-cidr" => {
                let cidr = Cidr::parse(value)?;
                if !cidr.address.is_ipv4() {
                    return Err("source policy requires IPv4".into());
                }
                Ok(Self::Source(cidr))
            }
            "destination-cidr" => Ok(Self::Destination(Cidr::parse(value)?)),
            "database-server" | "web-server" | "api-server" | "file-server" | "resource"
            | "gateway" => {
                let (permission, cidr) = value.split_once(':').ok_or("missing permission")?;
                let permission = match permission {
                    "r" => Permission::Read,
                    "w" => Permission::Write,
                    "rw" => Permission::ReadWrite,
                    _ => return Err("invalid permission".into()),
                };
                Ok(Self::Service {
                    category: category.into(),
                    permission,
                    cidr: Cidr::parse(cidr)?,
                })
            }
            _ => Err("unknown access policy".into()),
        }
    }
}
