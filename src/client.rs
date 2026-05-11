use std::net::SocketAddr;
use std::time::Duration;

use log::debug;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::codec;
use crate::error::{Result, SnmpError};
use crate::types::*;

/// Async SNMP client for v1/v2c.
pub struct SnmpClient {
    socket: UdpSocket,
    target: SocketAddr,
    community: Vec<u8>,
    version: Version,
    timeout: Duration,
    request_id: i32,
}

impl SnmpClient {
    /// Create a new SNMPv2c client.
    pub async fn new(target: &str, community: &str) -> Result<Self> {
        Self::with_version(target, community, Version::V2c).await
    }

    /// Create a client with a specific SNMP version.
    pub async fn with_version(target: &str, community: &str, version: Version) -> Result<Self> {
        let target_addr: SocketAddr = if target.contains(':') {
            target.parse().map_err(|e| SnmpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?
        } else {
            format!("{}:161", target).parse().map_err(|e| SnmpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?
        };

        let bind_addr = if target_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(Self {
            socket,
            target: target_addr,
            community: community.as_bytes().to_vec(),
            version,
            timeout: Duration::from_secs(5),
            request_id: rand::random::<i32>().abs(),
        })
    }

    /// Set request timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    fn next_request_id(&mut self) -> i32 {
        self.request_id = self.request_id.wrapping_add(1);
        if self.request_id < 0 { self.request_id = 1; }
        self.request_id
    }

    async fn send_and_recv(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.socket.send_to(packet, self.target).await?;
        let mut buf = vec![0u8; 65535];
        let len = timeout(self.timeout, self.socket.recv(&mut buf))
            .await
            .map_err(|_| SnmpError::Timeout)?
            .map_err(SnmpError::Io)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// SNMP GET — retrieve one or more OIDs.
    pub async fn get(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let req_id = self.next_request_id();
        let packet = codec::encode_get_request(self.version, &self.community, req_id, oids);
        debug!("GET request_id={} oids={}", req_id, oids.len());
        let resp_data = self.send_and_recv(&packet).await?;
        let resp = codec::decode_response(&resp_data)?;
        if resp.error_status != 0 {
            return Err(SnmpError::Snmp { status: resp.error_status, index: resp.error_index });
        }
        Ok(resp.varbinds)
    }

    /// SNMP GET for a single OID — convenience method.
    pub async fn get_one(&mut self, oid: &Oid) -> Result<VarBind> {
        let results = self.get(&[oid.clone()]).await?;
        results.into_iter().next().ok_or_else(|| SnmpError::Decode("empty response".into()))
    }

    /// SNMP GETNEXT — get the next OID(s) in the MIB tree.
    pub async fn get_next(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let req_id = self.next_request_id();
        let packet = codec::encode_getnext_request(self.version, &self.community, req_id, oids);
        debug!("GETNEXT request_id={}", req_id);
        let resp_data = self.send_and_recv(&packet).await?;
        let resp = codec::decode_response(&resp_data)?;
        if resp.error_status != 0 {
            return Err(SnmpError::Snmp { status: resp.error_status, index: resp.error_index });
        }
        Ok(resp.varbinds)
    }

    /// SNMP GETBULK — efficient bulk retrieval (v2c only).
    pub async fn get_bulk(&mut self, oids: &[Oid], non_repeaters: i32, max_repetitions: i32) -> Result<Vec<VarBind>> {
        let req_id = self.next_request_id();
        let packet = codec::encode_getbulk_request(
            self.version, &self.community, req_id, non_repeaters, max_repetitions, oids,
        );
        debug!("GETBULK request_id={} max_rep={}", req_id, max_repetitions);
        let resp_data = self.send_and_recv(&packet).await?;
        let resp = codec::decode_response(&resp_data)?;
        if resp.error_status != 0 {
            return Err(SnmpError::Snmp { status: resp.error_status, index: resp.error_index });
        }
        Ok(resp.varbinds)
    }

    /// SNMP SET — set one or more OID values.
    pub async fn set(&mut self, varbinds: &[VarBind]) -> Result<Vec<VarBind>> {
        let req_id = self.next_request_id();
        let packet = codec::encode_set_request(self.version, &self.community, req_id, varbinds);
        debug!("SET request_id={}", req_id);
        let resp_data = self.send_and_recv(&packet).await?;
        let resp = codec::decode_response(&resp_data)?;
        if resp.error_status != 0 {
            return Err(SnmpError::Snmp { status: resp.error_status, index: resp.error_index });
        }
        Ok(resp.varbinds)
    }

    /// Walk a subtree using GETNEXT (v1) or GETBULK (v2c).
    /// Returns all VarBinds under the given OID prefix.
    pub async fn walk(&mut self, root: &Oid) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        let mut current = root.clone();
        let root_prefix = root.components().to_vec();

        loop {
            let varbinds = if self.version == Version::V1 {
                self.get_next(&[current.clone()]).await?
            } else {
                self.get_bulk(&[current.clone()], 0, 20).await?
            };

            if varbinds.is_empty() {
                break;
            }

            let mut done = false;
            for vb in varbinds {
                // Check if still under root prefix
                let c = vb.oid.components();
                if c.len() < root_prefix.len() || c[..root_prefix.len()] != root_prefix[..] {
                    done = true;
                    break;
                }
                // Check for end-of-mib markers
                if matches!(vb.value, Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance) {
                    done = true;
                    break;
                }
                current = vb.oid.clone();
                results.push(vb);
            }

            if done {
                break;
            }
        }

        Ok(results)
    }
}
