//! SNMPv3 async client with USM support.

use std::net::SocketAddr;
use std::time::Duration;

use log::debug;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::codec::{self, BerEncoder};
use crate::error::{Result, SnmpError};
use crate::types::*;
use crate::v3::*;

/// Async SNMPv3 client with USM authentication and privacy.
pub struct SnmpV3Client {
    socket: UdpSocket,
    target: SocketAddr,
    credentials: UsmCredentials,
    engine: EngineState,
    timeout_duration: Duration,
    msg_id: i32,
    request_id: i32,
    salt: u64,
    auth_key: Option<Vec<u8>>,
    priv_key: Option<Vec<u8>>,
}

impl SnmpV3Client {
    /// Create a new SNMPv3 client and perform engine discovery.
    pub async fn new(target: &str, credentials: UsmCredentials) -> Result<Self> {
        let target_addr: SocketAddr = if target.contains(':') {
            target.parse().map_err(|e| SnmpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?
        } else {
            format!("{}:161", target).parse().map_err(|e| SnmpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?
        };

        let bind_addr = if target_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind_addr).await?;

        let mut client = Self {
            socket,
            target: target_addr,
            credentials,
            engine: EngineState::default(),
            timeout_duration: Duration::from_secs(5),
            msg_id: rand::random::<i32>().abs(),
            request_id: rand::random::<i32>().abs(),
            salt: rand::random::<u64>(),
            auth_key: None,
            priv_key: None,
        };

        client.discover_engine().await?;
        client.derive_keys();

        Ok(client)
    }

    /// Set request timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout_duration = timeout;
    }

    fn next_msg_id(&mut self) -> i32 {
        self.msg_id = self.msg_id.wrapping_add(1);
        if self.msg_id < 0 { self.msg_id = 1; }
        self.msg_id
    }

    fn next_request_id(&mut self) -> i32 {
        self.request_id = self.request_id.wrapping_add(1);
        if self.request_id < 0 { self.request_id = 1; }
        self.request_id
    }

    fn next_salt(&mut self) -> u64 {
        self.salt = self.salt.wrapping_add(1);
        self.salt
    }

    fn derive_keys(&mut self) {
        if let (Some(proto), Some(pass)) = (self.credentials.auth_protocol, &self.credentials.auth_password) {
            self.auth_key = Some(password_to_key(proto, pass, &self.engine.engine_id));
            if let (Some(_priv_proto), Some(priv_pass)) = (self.credentials.priv_protocol, &self.credentials.priv_password) {
                self.priv_key = Some(password_to_key(proto, priv_pass, &self.engine.engine_id));
            }
        }
    }

    async fn send_and_recv(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.socket.send_to(packet, self.target).await?;
        let mut buf = vec![0u8; 65535];
        let len = timeout(self.timeout_duration, self.socket.recv(&mut buf))
            .await
            .map_err(|_| SnmpError::Timeout)?
            .map_err(SnmpError::Io)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Perform engine discovery (RFC 3414 Section 4).
    async fn discover_engine(&mut self) -> Result<()> {
        debug!("SNMPv3 engine discovery");

        let msg_id = self.next_msg_id();
        let varbind_data = encode_empty_varbinds();
        let scoped_pdu = encode_scoped_pdu(
            &[], b"", V3_PDU_GET, 0, 0, 0, &varbind_data,
        );
        let security_params = encode_usm_params(&[], 0, 0, &[], &[], &[]);
        // flags: reportable (0x04), no auth, no priv
        let packet = encode_v3_message(msg_id, 65507, 0x04, 3, &security_params, &scoped_pdu, false);

        let resp_data = self.send_and_recv(&packet).await?;
        let msg = decode_v3_message(&resp_data)?;

        if msg.engine_id.is_empty() {
            return Err(SnmpError::DiscoveryFailed);
        }

        self.engine = EngineState {
            engine_id: msg.engine_id,
            engine_boots: msg.engine_boots,
            engine_time: msg.engine_time,
        };

        debug!("Discovered engine_id={:?} boots={} time={}",
            self.engine.engine_id, self.engine.engine_boots, self.engine.engine_time);
        Ok(())
    }

    /// Build and send an authenticated/encrypted request.
    async fn send_request(&mut self, pdu_type: u8, varbind_data: &[u8]) -> Result<Vec<VarBind>> {
        let msg_id = self.next_msg_id();
        let request_id = self.next_request_id();
        let flags = self.credentials.security_level() | 0x04; // + reportable

        let scoped_pdu = encode_scoped_pdu(
            &self.engine.engine_id,
            b"",
            pdu_type,
            request_id,
            0, 0,
            varbind_data,
        );

        // Encrypt if needed
        let (final_pdu, priv_params) = if let Some(priv_proto) = self.credentials.priv_protocol {
            let priv_key = self.priv_key.clone().unwrap();
            let salt = self.next_salt();
            let (encrypted, pp) = encrypt(
                priv_proto, &priv_key,
                self.engine.engine_boots, self.engine.engine_time,
                salt, &scoped_pdu,
            );
            (encrypted, pp)
        } else {
            (scoped_pdu, vec![])
        };

        let is_encrypted = self.credentials.priv_protocol.is_some();

        // Build security params with empty auth (placeholder)
        let auth_placeholder_len = self.credentials.auth_protocol
            .map(|p| truncated_hmac_len_pub(p))
            .unwrap_or(0);
        let auth_placeholder = vec![0u8; auth_placeholder_len];

        let security_params = encode_usm_params(
            &self.engine.engine_id,
            self.engine.engine_boots,
            self.engine.engine_time,
            &self.credentials.username,
            &auth_placeholder,
            &priv_params,
        );

        let mut packet = encode_v3_message(
            msg_id, 65507, flags, 3, &security_params, &final_pdu, is_encrypted,
        );

        // Apply authentication HMAC
        if let (Some(proto), Some(auth_key)) = (self.credentials.auth_protocol, &self.auth_key) {
            let mac = compute_auth(proto, auth_key, &packet);
            // Find and replace the auth placeholder in the packet
            if let Some(pos) = find_auth_placeholder(&packet, auth_placeholder_len) {
                packet[pos..pos + mac.len()].copy_from_slice(&mac);
            }
        }

        let resp_data = self.send_and_recv(&packet).await?;
        let msg = decode_v3_message(&resp_data)?;

        // Update engine time
        self.engine.engine_boots = msg.engine_boots;
        self.engine.engine_time = msg.engine_time;

        // Verify auth if applicable
        if let (Some(proto), Some(auth_key)) = (self.credentials.auth_protocol, &self.auth_key) {
            if !msg.auth_params.is_empty() {
                let mut verify_data = resp_data.clone();
                // Zero out auth params in the message for verification
                if let Some(pos) = find_auth_placeholder(&verify_data, msg.auth_params.len()) {
                    for b in &mut verify_data[pos..pos + msg.auth_params.len()] {
                        *b = 0;
                    }
                }
                if !verify_auth(proto, auth_key, &verify_data, &msg.auth_params) {
                    return Err(SnmpError::AuthFailed);
                }
            }
        }

        // Decrypt if needed
        let pdu_data = if msg.is_encrypted {
            if let (Some(priv_proto), Some(priv_key)) = (self.credentials.priv_protocol, &self.priv_key) {
                decrypt(
                    priv_proto, priv_key,
                    msg.engine_boots, msg.engine_time,
                    &msg.priv_params, &msg.scoped_pdu_raw,
                )?
            } else {
                return Err(SnmpError::DecryptFailed);
            }
        } else {
            msg.scoped_pdu_raw
        };

        let scoped = decode_scoped_pdu(&pdu_data)?;
        if scoped.error_status != 0 {
            return Err(SnmpError::Snmp { status: scoped.error_status, index: scoped.error_index });
        }

        Ok(scoped.varbinds)
    }

    /// SNMP GET.
    pub async fn get(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let varbind_data = encode_null_varbinds(oids);
        self.send_request(V3_PDU_GET, &varbind_data).await
    }

    /// SNMP GET for a single OID.
    pub async fn get_one(&mut self, oid: &Oid) -> Result<VarBind> {
        let results = self.get(&[oid.clone()]).await?;
        results.into_iter().next().ok_or_else(|| SnmpError::Decode("empty response".into()))
    }

    /// SNMP GETNEXT.
    pub async fn get_next(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let varbind_data = encode_null_varbinds(oids);
        self.send_request(V3_PDU_GETNEXT, &varbind_data).await
    }

    /// SNMP GETBULK.
    pub async fn get_bulk(&mut self, oids: &[Oid], non_repeaters: i32, max_repetitions: i32) -> Result<Vec<VarBind>> {
        let msg_id = self.next_msg_id();
        let request_id = self.next_request_id();
        let flags = self.credentials.security_level() | 0x04;

        let varbind_data = encode_null_varbinds(oids);

        // GETBULK uses non_repeaters/max_repetitions instead of error_status/error_index
        let scoped_pdu = encode_scoped_pdu(
            &self.engine.engine_id, b"",
            V3_PDU_GETBULK, request_id,
            non_repeaters, max_repetitions,
            &varbind_data,
        );

        let (final_pdu, priv_params) = if let Some(priv_proto) = self.credentials.priv_protocol {
            let priv_key = self.priv_key.clone().unwrap();
            let salt = self.next_salt();
            let (encrypted, pp) = encrypt(
                priv_proto, &priv_key,
                self.engine.engine_boots, self.engine.engine_time,
                salt, &scoped_pdu,
            );
            (encrypted, pp)
        } else {
            (scoped_pdu, vec![])
        };

        let is_encrypted = self.credentials.priv_protocol.is_some();
        let auth_placeholder_len = self.credentials.auth_protocol
            .map(|p| truncated_hmac_len_pub(p))
            .unwrap_or(0);
        let auth_placeholder = vec![0u8; auth_placeholder_len];

        let security_params = encode_usm_params(
            &self.engine.engine_id,
            self.engine.engine_boots, self.engine.engine_time,
            &self.credentials.username,
            &auth_placeholder, &priv_params,
        );

        let mut packet = encode_v3_message(
            msg_id, 65507, flags, 3, &security_params, &final_pdu, is_encrypted,
        );

        if let (Some(proto), Some(auth_key)) = (self.credentials.auth_protocol, &self.auth_key) {
            let mac = compute_auth(proto, auth_key, &packet);
            if let Some(pos) = find_auth_placeholder(&packet, auth_placeholder_len) {
                packet[pos..pos + mac.len()].copy_from_slice(&mac);
            }
        }

        let resp_data = self.send_and_recv(&packet).await?;
        let msg = decode_v3_message(&resp_data)?;
        self.engine.engine_boots = msg.engine_boots;
        self.engine.engine_time = msg.engine_time;

        let pdu_data = if msg.is_encrypted {
            if let (Some(priv_proto), Some(priv_key)) = (self.credentials.priv_protocol, &self.priv_key) {
                decrypt(priv_proto, priv_key, msg.engine_boots, msg.engine_time, &msg.priv_params, &msg.scoped_pdu_raw)?
            } else {
                return Err(SnmpError::DecryptFailed);
            }
        } else {
            msg.scoped_pdu_raw
        };

        let scoped = decode_scoped_pdu(&pdu_data)?;
        if scoped.error_status != 0 {
            return Err(SnmpError::Snmp { status: scoped.error_status, index: scoped.error_index });
        }
        Ok(scoped.varbinds)
    }

    /// SNMP SET.
    pub async fn set(&mut self, varbinds: &[VarBind]) -> Result<Vec<VarBind>> {
        let varbind_data = encode_set_varbinds(varbinds);
        self.send_request(V3_PDU_SET, &varbind_data).await
    }

    /// Walk a subtree.
    pub async fn walk(&mut self, root: &Oid) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        let mut current = root.clone();
        let root_prefix = root.components().to_vec();

        loop {
            let varbinds = self.get_bulk(&[current.clone()], 0, 20).await?;
            if varbinds.is_empty() {
                break;
            }

            let mut done = false;
            for vb in varbinds {
                let c = vb.oid.components();
                if c.len() < root_prefix.len() || c[..root_prefix.len()] != root_prefix[..] {
                    done = true;
                    break;
                }
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

// --- Helpers ---

fn encode_empty_varbinds() -> Vec<u8> {
    Vec::new()
}

fn encode_null_varbinds(oids: &[Oid]) -> Vec<u8> {
    let mut inner = BerEncoder::new();
    for oid in oids {
        let mut vb = BerEncoder::new();
        vb.write_oid(oid);
        vb.write_null();
        let vb_bytes = vb.into_bytes();
        inner.write_sequence(&vb_bytes);
    }
    inner.into_bytes()
}

fn encode_set_varbinds(varbinds: &[VarBind]) -> Vec<u8> {
    let mut inner = BerEncoder::new();
    for vb in varbinds {
        let mut enc = BerEncoder::new();
        enc.write_oid(&vb.oid);
        codec::encode_value_pub(&mut enc, &vb.value);
        let vb_bytes = enc.into_bytes();
        inner.write_sequence(&vb_bytes);
    }
    inner.into_bytes()
}

fn truncated_hmac_len_pub(protocol: AuthProtocol) -> usize {
    match protocol {
        AuthProtocol::Md5 => 12,
        AuthProtocol::Sha1 => 12,
        AuthProtocol::Sha256 => 24,
    }
}

/// Find the position of the auth placeholder (all zeros) in the packet.
fn find_auth_placeholder(packet: &[u8], len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let zeros = vec![0u8; len];
    packet.windows(len).position(|w| w == zeros.as_slice())
}
