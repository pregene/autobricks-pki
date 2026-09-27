use crate::Result;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy)]
pub struct ListenerConfig {
    pub bind: IpAddr,
    pub tls_port: u16,
    pub https_port: u16,
}

impl ListenerConfig {
    pub fn parse(bind: &str, tls_port: &str, https_port: &str) -> Result<Self> {
        let config = Self {
            bind: bind.parse()?,
            tls_port: tls_port.parse()?,
            https_port: https_port.parse()?,
        };
        if config.tls_port == 0 || config.https_port == 0 {
            return Err("listener ports must be between 1 and 65535".into());
        }
        if config.tls_port == config.https_port {
            return Err("TLS and HTTPS listeners require different ports".into());
        }
        Ok(config)
    }

    pub fn tls_address(self) -> SocketAddr {
        SocketAddr::new(self.bind, self.tls_port)
    }

    pub fn https_address(self) -> SocketAddr {
        SocketAddr::new(self.bind, self.https_port)
    }
}
