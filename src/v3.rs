//! SNMPv3 User-based Security Model (USM) implementation.

use crate::codec::{BerDecoder, BerEncoder};
use crate::error::{Result, SnmpError};
use crate::types::VarBind;

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use block_padding;

/// SNMPv3 authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Md5,
    Sha1,
    Sha256,
}

/// SNMPv3 privacy protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    Des,
    Aes128,
}

/// SNMPv3 USM credentials.
#[derive(Debug, Clone)]
pub struct UsmCredentials {
    pub username: Vec<u8>,
    pub auth_protocol: Option<AuthProtocol>,
    pub auth_password: Option<Vec<u8>>,
    pub priv_protocol: Option<PrivProtocol>,
    pub priv_password: Option<Vec<u8>>,
}

impl UsmCredentials {
    pub fn no_auth(username: &str) -> Self {
        Self {
            username: username.as_bytes().to_vec(),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
        }
    }

    pub fn auth_only(username: &str, protocol: AuthProtocol, password: &str) -> Self {
        Self {
            username: username.as_bytes().to_vec(),
            auth_protocol: Some(protocol),
            auth_password: Some(password.as_bytes().to_vec()),
            priv_protocol: None,
            priv_password: None,
        }
    }

    pub fn auth_priv(
        username: &str,
        auth_protocol: AuthProtocol,
        auth_password: &str,
        priv_protocol: PrivProtocol,
        priv_password: &str,
    ) -> Self {
        Self {
            username: username.as_bytes().to_vec(),
            auth_protocol: Some(auth_protocol),
            auth_password: Some(auth_password.as_bytes().to_vec()),
            priv_protocol: Some(priv_protocol),
            priv_password: Some(priv_password.as_bytes().to_vec()),
        }
    }

    /// Security level flags for the msgFlags field.
    pub fn security_level(&self) -> u8 {
        let mut flags = 0u8;
        if self.auth_protocol.is_some() {
            flags |= 0x01; // authFlag
        }
        if self.priv_protocol.is_some() {
            flags |= 0x02; // privFlag
        }
        flags
    }
}

/// SNMPv3 engine discovery state.
#[derive(Debug, Clone, Default)]
pub struct EngineState {
    pub engine_id: Vec<u8>,
    pub engine_boots: u32,
    pub engine_time: u32,
}

// --- Key Localization (RFC 3414) ---

/// Password to key using the standard key localization algorithm.
pub fn password_to_key(protocol: AuthProtocol, password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let master_key = password_to_master_key(protocol, password);
    localize_key(protocol, &master_key, engine_id)
}

fn password_to_master_key(protocol: AuthProtocol, password: &[u8]) -> Vec<u8> {
    // RFC 3414 Section 2.6: password to key algorithm
    // Process 1MB of repeated password through hash
    let count = 1_048_576; // 1MB
    let pass_len = password.len();
    if pass_len == 0 {
        return vec![0u8; digest_len(protocol)];
    }

    match protocol {
        AuthProtocol::Md5 => {
            use md5::Digest;
            let mut hasher = Md5::new();
            let mut i = 0;
            while i < count {
                let chunk_end = std::cmp::min(i + 64, count);
                let chunk_len = chunk_end - i;
                let mut buf = [0u8; 64];
                for j in 0..chunk_len {
                    buf[j] = password[(i + j) % pass_len];
                }
                hasher.update(&buf[..chunk_len]);
                i += chunk_len;
            }
            hasher.finalize().to_vec()
        }
        AuthProtocol::Sha1 => {
            use sha1::Digest;
            let mut hasher = Sha1::new();
            let mut i = 0;
            while i < count {
                let chunk_end = std::cmp::min(i + 64, count);
                let chunk_len = chunk_end - i;
                let mut buf = [0u8; 64];
                for j in 0..chunk_len {
                    buf[j] = password[(i + j) % pass_len];
                }
                hasher.update(&buf[..chunk_len]);
                i += chunk_len;
            }
            hasher.finalize().to_vec()
        }
        AuthProtocol::Sha256 => {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            let mut i = 0;
            while i < count {
                let chunk_end = std::cmp::min(i + 64, count);
                let chunk_len = chunk_end - i;
                let mut buf = [0u8; 64];
                for j in 0..chunk_len {
                    buf[j] = password[(i + j) % pass_len];
                }
                hasher.update(&buf[..chunk_len]);
                i += chunk_len;
            }
            hasher.finalize().to_vec()
        }
    }
}

fn localize_key(protocol: AuthProtocol, master_key: &[u8], engine_id: &[u8]) -> Vec<u8> {
    match protocol {
        AuthProtocol::Md5 => {
            use md5::Digest;
            let mut hasher = Md5::new();
            hasher.update(master_key);
            hasher.update(engine_id);
            hasher.update(master_key);
            hasher.finalize().to_vec()
        }
        AuthProtocol::Sha1 => {
            use sha1::Digest;
            let mut hasher = Sha1::new();
            hasher.update(master_key);
            hasher.update(engine_id);
            hasher.update(master_key);
            hasher.finalize().to_vec()
        }
        AuthProtocol::Sha256 => {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(master_key);
            hasher.update(engine_id);
            hasher.update(master_key);
            hasher.finalize().to_vec()
        }
    }
}

fn digest_len(protocol: AuthProtocol) -> usize {
    match protocol {
        AuthProtocol::Md5 => 16,
        AuthProtocol::Sha1 => 20,
        AuthProtocol::Sha256 => 32,
    }
}

fn truncated_hmac_len(protocol: AuthProtocol) -> usize {
    match protocol {
        AuthProtocol::Md5 => 12,
        AuthProtocol::Sha1 => 12,
        AuthProtocol::Sha256 => 24,
    }
}

// --- Authentication ---

/// Compute HMAC for authentication.
pub fn compute_auth(protocol: AuthProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    let trunc_len = truncated_hmac_len(protocol);
    let mac = match protocol {
        AuthProtocol::Md5 => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).unwrap();
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    mac[..trunc_len].to_vec()
}

/// Verify HMAC authentication.
pub fn verify_auth(protocol: AuthProtocol, key: &[u8], message: &[u8], expected: &[u8]) -> bool {
    let computed = compute_auth(protocol, key, message);
    // Constant-time comparison
    if computed.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// --- Privacy (Encryption/Decryption) ---

/// Encrypt scoped PDU data.
pub fn encrypt(
    priv_protocol: PrivProtocol,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: u64,
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    match priv_protocol {
        PrivProtocol::Des => encrypt_des(priv_key, engine_boots, salt as u32, data),
        PrivProtocol::Aes128 => encrypt_aes128(priv_key, engine_boots, engine_time, salt, data),
    }
}

/// Decrypt scoped PDU data.
pub fn decrypt(
    priv_protocol: PrivProtocol,
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    priv_params: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    match priv_protocol {
        PrivProtocol::Des => decrypt_des(priv_key, priv_params, data),
        PrivProtocol::Aes128 => decrypt_aes128(priv_key, engine_boots, engine_time, priv_params, data),
    }
}

fn encrypt_des(priv_key: &[u8], engine_boots: u32, salt: u32, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type DesCbcEnc = cbc::Encryptor<des::Des>;

    let des_key = &priv_key[..8];
    let pre_iv = &priv_key[8..16];

    // Salt = engine_boots (4 bytes) + random salt (4 bytes)
    let mut salt_bytes = Vec::with_capacity(8);
    salt_bytes.extend_from_slice(&engine_boots.to_be_bytes());
    salt_bytes.extend_from_slice(&salt.to_be_bytes());

    // IV = pre_iv XOR salt
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ salt_bytes[i];
    }

    // Pad data to 8-byte boundary
    let pad_len = (8 - (data.len() % 8)) % 8;
    let mut padded = data.to_vec();
    padded.extend(vec![0u8; pad_len]);

    let cipher = DesCbcEnc::new_from_slices(des_key, &iv).unwrap();
    let encrypted = cipher.encrypt_padded_vec_mut::<block_padding::NoPadding>(&padded);

    (encrypted, salt_bytes)
}

fn decrypt_des(priv_key: &[u8], priv_params: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    type DesCbcDec = cbc::Decryptor<des::Des>;

    if priv_params.len() != 8 {
        return Err(SnmpError::DecryptFailed);
    }

    let des_key = &priv_key[..8];
    let pre_iv = &priv_key[8..16];

    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ priv_params[i];
    }

    let cipher = DesCbcDec::new_from_slices(des_key, &iv).map_err(|_| SnmpError::DecryptFailed)?;
    cipher
        .decrypt_padded_vec_mut::<block_padding::NoPadding>(data)
        .map_err(|_| SnmpError::DecryptFailed)
}

fn encrypt_aes128(priv_key: &[u8], engine_boots: u32, engine_time: u32, salt: u64, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    type Aes128Cfb = cfb_mode::Encryptor<aes::Aes128>;

    let aes_key = &priv_key[..16];

    // IV = engine_boots(4) + engine_time(4) + salt(8)
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(&salt.to_be_bytes());

    let salt_bytes = salt.to_be_bytes().to_vec();

    let mut encrypted = data.to_vec();
    let cipher = Aes128Cfb::new_from_slices(aes_key, &iv).unwrap();
    cipher.encrypt(&mut encrypted);

    (encrypted, salt_bytes)
}

fn decrypt_aes128(priv_key: &[u8], engine_boots: u32, engine_time: u32, priv_params: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    type Aes128Cfb = cfb_mode::Decryptor<aes::Aes128>;

    if priv_params.len() != 8 {
        return Err(SnmpError::DecryptFailed);
    }

    let aes_key = &priv_key[..16];

    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(priv_params);

    let mut decrypted = data.to_vec();
    let cipher = Aes128Cfb::new_from_slices(aes_key, &iv).map_err(|_| SnmpError::DecryptFailed)?;
    cipher.decrypt(&mut decrypted);

    Ok(decrypted)
}

// --- SNMPv3 Message Encoding/Decoding ---

/// Encode an SNMPv3 message.
pub fn encode_v3_message(
    msg_id: i32,
    max_size: i32,
    flags: u8,
    security_model: i32,
    security_params: &[u8],
    scoped_pdu: &[u8],
    encrypted: bool,
) -> Vec<u8> {
    // msgGlobalData (HeaderData)
    let mut header = BerEncoder::new();
    header.write_integer(msg_id as i64);
    header.write_integer(max_size as i64);
    header.write_octet_string(&[flags]);
    header.write_integer(security_model as i64);
    let header_bytes = header.into_bytes();

    let mut msg = BerEncoder::new();
    msg.write_integer(3); // version
    msg.write_sequence(&header_bytes);
    msg.write_octet_string(security_params);
    if encrypted {
        msg.write_octet_string(scoped_pdu);
    } else {
        // scoped PDU is already a SEQUENCE, write raw
        msg.buf_extend(scoped_pdu);
    }
    let msg_bytes = msg.into_bytes();

    let mut out = BerEncoder::new();
    out.write_sequence(&msg_bytes);
    out.into_bytes()
}

/// Encode USM security parameters.
pub fn encode_usm_params(
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    username: &[u8],
    auth_params: &[u8],
    priv_params: &[u8],
) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.write_octet_string(engine_id);
    enc.write_integer(engine_boots as i64);
    enc.write_integer(engine_time as i64);
    enc.write_octet_string(username);
    enc.write_octet_string(auth_params);
    enc.write_octet_string(priv_params);
    let inner = enc.into_bytes();

    let mut out = BerEncoder::new();
    out.write_sequence(&inner);
    out.into_bytes()
}

/// Encode a scoped PDU.
pub fn encode_scoped_pdu(
    engine_id: &[u8],
    context_name: &[u8],
    pdu_type: u8,
    request_id: i32,
    error_status: i32,
    error_index: i32,
    varbind_data: &[u8],
) -> Vec<u8> {
    let mut pdu = BerEncoder::new();
    pdu.write_integer(request_id as i64);
    pdu.write_integer(error_status as i64);
    pdu.write_integer(error_index as i64);
    pdu.write_sequence(varbind_data);
    let pdu_bytes = pdu.into_bytes();

    let mut scoped = BerEncoder::new();
    scoped.write_octet_string(engine_id);
    scoped.write_octet_string(context_name);
    scoped.write_tagged(pdu_type, &pdu_bytes);
    let scoped_bytes = scoped.into_bytes();

    let mut out = BerEncoder::new();
    out.write_sequence(&scoped_bytes);
    out.into_bytes()
}

/// Decoded SNMPv3 message.
#[derive(Debug)]
pub struct V3Message {
    pub msg_id: i32,
    pub max_size: i32,
    pub flags: u8,
    pub security_model: i32,
    pub security_params_raw: Vec<u8>,
    pub engine_id: Vec<u8>,
    pub engine_boots: u32,
    pub engine_time: u32,
    pub username: Vec<u8>,
    pub auth_params: Vec<u8>,
    pub priv_params: Vec<u8>,
    pub scoped_pdu_raw: Vec<u8>,
    pub is_encrypted: bool,
}

/// Decoded scoped PDU content.
#[derive(Debug)]
pub struct ScopedPduData {
    pub context_engine_id: Vec<u8>,
    pub context_name: Vec<u8>,
    pub pdu_type: u8,
    pub request_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Vec<VarBind>,
}

/// Decode an SNMPv3 message.
pub fn decode_v3_message(data: &[u8]) -> Result<V3Message> {
    let mut dec = BerDecoder::new(data);
    let mut msg = dec.read_sequence()?;

    let version = msg.read_integer()?;
    if version != 3 {
        return Err(SnmpError::Decode(format!("expected v3, got version {}", version)));
    }

    // Header
    let mut header = msg.read_sequence()?;
    let msg_id = header.read_integer()? as i32;
    let max_size = header.read_integer()? as i32;
    let flags_bytes = header.read_octet_string()?;
    let flags = if flags_bytes.is_empty() { 0 } else { flags_bytes[0] };
    let security_model = header.read_integer()? as i32;

    // Security parameters (OCTET STRING wrapping a SEQUENCE)
    let security_params_raw = msg.read_octet_string()?.to_vec();
    let (engine_id, engine_boots, engine_time, username, auth_params, priv_params) =
        decode_usm_params(&security_params_raw)?;

    // Scoped PDU (either plaintext SEQUENCE or encrypted OCTET STRING)
    let is_encrypted = flags & 0x02 != 0;
    let scoped_pdu_raw = if is_encrypted {
        msg.read_octet_string()?.to_vec()
    } else {
        // Read remaining as raw bytes (it's a SEQUENCE)
        let _tag = msg.peek_tag()?;
        let (_, raw) = msg.read_tlv_with_header()?;
        raw
    };

    Ok(V3Message {
        msg_id,
        max_size,
        flags,
        security_model,
        security_params_raw,
        engine_id,
        engine_boots,
        engine_time,
        username,
        auth_params,
        priv_params,
        scoped_pdu_raw,
        is_encrypted,
    })
}

/// Decode scoped PDU data.
pub fn decode_scoped_pdu(data: &[u8]) -> Result<ScopedPduData> {
    let mut dec = BerDecoder::new(data);
    let mut seq = dec.read_sequence()?;

    let context_engine_id = seq.read_octet_string()?.to_vec();
    let context_name = seq.read_octet_string()?.to_vec();

    // PDU
    let pdu_type = seq.read_tag()?;
    let pdu_len = seq.read_length()?;
    let pdu_data = seq.read_raw(pdu_len)?;
    let mut pdu = BerDecoder::new(pdu_data);

    let request_id = pdu.read_integer()? as i32;
    let error_status = pdu.read_integer()? as u32;
    let error_index = pdu.read_integer()? as u32;

    let mut vbl = pdu.read_sequence()?;
    let mut varbinds = Vec::new();
    while vbl.remaining() > 0 {
        let mut vb_dec = vbl.read_sequence()?;
        let oid = vb_dec.read_oid()?;
        let value = vb_dec.read_value()?;
        varbinds.push(VarBind { oid, value });
    }

    Ok(ScopedPduData {
        context_engine_id,
        context_name,
        pdu_type,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}

fn decode_usm_params(data: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>, Vec<u8>, Vec<u8>)> {
    if data.is_empty() {
        return Ok((vec![], 0, 0, vec![], vec![], vec![]));
    }
    let mut dec = BerDecoder::new(data);
    let mut seq = dec.read_sequence()?;
    let engine_id = seq.read_octet_string()?.to_vec();
    let engine_boots = seq.read_integer()? as u32;
    let engine_time = seq.read_integer()? as u32;
    let username = seq.read_octet_string()?.to_vec();
    let auth_params = seq.read_octet_string()?.to_vec();
    let priv_params = seq.read_octet_string()?.to_vec();
    Ok((engine_id, engine_boots, engine_time, username, auth_params, priv_params))
}

// PDU type constants re-exported for v3 usage
pub const V3_PDU_GET: u8 = 0xA0;
pub const V3_PDU_GETNEXT: u8 = 0xA1;
pub const V3_PDU_RESPONSE: u8 = 0xA2;
pub const V3_PDU_SET: u8 = 0xA3;
pub const V3_PDU_GETBULK: u8 = 0xA5;
pub const V3_PDU_REPORT: u8 = 0xA8;
