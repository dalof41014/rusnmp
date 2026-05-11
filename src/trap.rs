//! SNMP Trap receiver (v1/v2c/v3).

use std::net::SocketAddr;

use log::debug;
use tokio::net::UdpSocket;

use crate::codec::BerDecoder;
use crate::error::{Result, SnmpError};
use crate::types::*;

/// A received SNMP trap/notification.
#[derive(Debug, Clone)]
pub struct Trap {
    /// Source address of the trap sender.
    pub source: SocketAddr,
    /// SNMP version.
    pub version: Version,
    /// Community string (v1/v2c) or empty for v3.
    pub community: Vec<u8>,
    /// Variable bindings in the trap.
    pub varbinds: Vec<VarBind>,
    /// SNMPv1: enterprise OID.
    pub enterprise: Option<Oid>,
    /// SNMPv1: agent address.
    pub agent_addr: Option<[u8; 4]>,
    /// SNMPv1: generic trap type.
    pub generic_trap: Option<i32>,
    /// SNMPv1: specific trap type.
    pub specific_trap: Option<i32>,
    /// SNMPv1: timestamp.
    pub timestamp: Option<u32>,
}

/// Async SNMP trap receiver.
pub struct TrapReceiver {
    socket: UdpSocket,
}

// PDU tags for traps
const PDU_TRAP_V1: u8 = 0xA4;
const PDU_TRAP_V2: u8 = 0xA7; // SNMPv2-Trap-PDU (InformRequest is 0xA6)

impl TrapReceiver {
    /// Bind a trap receiver on the given address (typically "0.0.0.0:162").
    pub async fn bind(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        debug!("Trap receiver listening on {}", addr);
        Ok(Self { socket })
    }

    /// Wait for and receive the next trap. Blocks until a trap arrives.
    pub async fn recv(&self) -> Result<Trap> {
        loop {
            let mut buf = vec![0u8; 65535];
            let (len, source) = self.socket.recv_from(&mut buf).await?;
            buf.truncate(len);

            match self.decode_trap(&buf, source) {
                Ok(trap) => return Ok(trap),
                Err(e) => {
                    debug!("Failed to decode trap from {}: {}", source, e);
                    continue;
                }
            }
        }
    }

    fn decode_trap(&self, data: &[u8], source: SocketAddr) -> Result<Trap> {
        let mut dec = BerDecoder::new(data);
        let mut msg = dec.read_sequence()?;

        let ver = msg.read_integer()?;
        let version = match ver {
            0 => Version::V1,
            1 => Version::V2c,
            3 => Version::V3,
            _ => return Err(SnmpError::Decode(format!("unknown version: {}", ver))),
        };

        match version {
            Version::V1 => self.decode_v1_trap(&mut msg, source),
            Version::V2c => self.decode_v2c_trap(&mut msg, source),
            Version::V3 => self.decode_v3_trap(&mut msg, source),
        }
    }

    fn decode_v1_trap(&self, msg: &mut BerDecoder<'_>, source: SocketAddr) -> Result<Trap> {
        let community = msg.read_octet_string()?.to_vec();

        let pdu_tag = msg.read_tag()?;
        if pdu_tag != PDU_TRAP_V1 {
            return Err(SnmpError::Decode(format!("expected Trap-PDU (0xA4), got 0x{:02X}", pdu_tag)));
        }
        let pdu_len = msg.read_length()?;
        let pdu_data = msg.read_raw(pdu_len)?;
        let mut pdu = BerDecoder::new(pdu_data);

        let enterprise = pdu.read_oid()?;

        // Agent address (APPLICATION 0, IpAddress)
        let (_tag, addr_data) = pdu.read_tlv()?;
        let agent_addr = if addr_data.len() == 4 {
            Some([addr_data[0], addr_data[1], addr_data[2], addr_data[3]])
        } else {
            None
        };

        let generic_trap = pdu.read_integer()? as i32;
        let specific_trap = pdu.read_integer()? as i32;
        let timestamp = pdu.read_integer()? as u32;

        // VarBind list
        let mut vbl = pdu.read_sequence()?;
        let mut varbinds = Vec::new();
        while vbl.remaining() > 0 {
            let mut vb_dec = vbl.read_sequence()?;
            let oid = vb_dec.read_oid()?;
            let value = vb_dec.read_value()?;
            varbinds.push(VarBind { oid, value });
        }

        Ok(Trap {
            source,
            version: Version::V1,
            community,
            varbinds,
            enterprise: Some(enterprise),
            agent_addr,
            generic_trap: Some(generic_trap),
            specific_trap: Some(specific_trap),
            timestamp: Some(timestamp),
        })
    }

    fn decode_v2c_trap(&self, msg: &mut BerDecoder<'_>, source: SocketAddr) -> Result<Trap> {
        let community = msg.read_octet_string()?.to_vec();

        let pdu_tag = msg.read_tag()?;
        if pdu_tag != PDU_TRAP_V2 {
            return Err(SnmpError::Decode(format!("expected v2-Trap (0xA7), got 0x{:02X}", pdu_tag)));
        }
        let pdu_len = msg.read_length()?;
        let pdu_data = msg.read_raw(pdu_len)?;
        let mut pdu = BerDecoder::new(pdu_data);

        let _request_id = pdu.read_integer()?;
        let _error_status = pdu.read_integer()?;
        let _error_index = pdu.read_integer()?;

        let mut vbl = pdu.read_sequence()?;
        let mut varbinds = Vec::new();
        while vbl.remaining() > 0 {
            let mut vb_dec = vbl.read_sequence()?;
            let oid = vb_dec.read_oid()?;
            let value = vb_dec.read_value()?;
            varbinds.push(VarBind { oid, value });
        }

        Ok(Trap {
            source,
            version: Version::V2c,
            community,
            varbinds,
            enterprise: None,
            agent_addr: None,
            generic_trap: None,
            specific_trap: None,
            timestamp: None,
        })
    }

    fn decode_v3_trap(&self, msg: &mut BerDecoder<'_>, source: SocketAddr) -> Result<Trap> {
        // For v3 traps, we do a simplified decode (no auth verification)
        // Full v3 trap handling would require USM credentials
        let mut header = msg.read_sequence()?;
        let _msg_id = header.read_integer()?;
        let _max_size = header.read_integer()?;
        let _flags = header.read_octet_string()?;
        let _security_model = header.read_integer()?;

        let _security_params = msg.read_octet_string()?;

        // Try to read scoped PDU
        let mut scoped = msg.read_sequence()?;
        let _context_engine_id = scoped.read_octet_string()?;
        let _context_name = scoped.read_octet_string()?;

        let _pdu_tag = scoped.read_tag()?;
        let pdu_len = scoped.read_length()?;
        let pdu_data = scoped.read_raw(pdu_len)?;
        let mut pdu = BerDecoder::new(pdu_data);

        let _request_id = pdu.read_integer()?;
        let _error_status = pdu.read_integer()?;
        let _error_index = pdu.read_integer()?;

        let mut vbl = pdu.read_sequence()?;
        let mut varbinds = Vec::new();
        while vbl.remaining() > 0 {
            let mut vb_dec = vbl.read_sequence()?;
            let oid = vb_dec.read_oid()?;
            let value = vb_dec.read_value()?;
            varbinds.push(VarBind { oid, value });
        }

        Ok(Trap {
            source,
            version: Version::V3,
            community: vec![],
            varbinds,
            enterprise: None,
            agent_addr: None,
            generic_trap: None,
            specific_trap: None,
            timestamp: None,
        })
    }
}
