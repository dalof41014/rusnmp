//! BER (Basic Encoding Rules) codec for SNMP PDUs.

use crate::error::{Result, SnmpError};
use crate::types::{Oid, Value, VarBind, Version};

// ASN.1 tag constants
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

// SNMP application tags
const TAG_IPADDRESS: u8 = 0x40;
const TAG_COUNTER32: u8 = 0x41;
const TAG_GAUGE32: u8 = 0x42;
const TAG_TIMETICKS: u8 = 0x43;
const TAG_OPAQUE: u8 = 0x44;
const TAG_COUNTER64: u8 = 0x46;

// SNMP exception tags (context-specific, primitive)
const TAG_NO_SUCH_OBJECT: u8 = 0x80;
const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
const TAG_END_OF_MIB_VIEW: u8 = 0x82;

// PDU types (context-specific, constructed)
const PDU_GET: u8 = 0xA0;
const PDU_GETNEXT: u8 = 0xA1;
const PDU_RESPONSE: u8 = 0xA2;
const PDU_SET: u8 = 0xA3;
const PDU_GETBULK: u8 = 0xA5;

// --- Encoder ---

pub struct BerEncoder {
    buf: Vec<u8>,
}

impl BerEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(512) }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn buf_extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn write_sequence(&mut self, content: &[u8]) {
        self.buf.push(TAG_SEQUENCE);
        self.write_length(content.len());
        self.buf.extend_from_slice(content);
    }

    pub fn write_tagged(&mut self, tag: u8, content: &[u8]) {
        self.buf.push(tag);
        self.write_length(content.len());
        self.buf.extend_from_slice(content);
    }

    pub fn write_integer(&mut self, val: i64) {
        let bytes = encode_integer_bytes(val);
        self.buf.push(TAG_INTEGER);
        self.write_length(bytes.len());
        self.buf.extend_from_slice(&bytes);
    }

    pub fn write_octet_string(&mut self, data: &[u8]) {
        self.buf.push(TAG_OCTET_STRING);
        self.write_length(data.len());
        self.buf.extend_from_slice(data);
    }

    pub fn write_null(&mut self) {
        self.buf.push(TAG_NULL);
        self.buf.push(0x00);
    }

    pub fn write_oid(&mut self, oid: &Oid) {
        let encoded = encode_oid(oid);
        self.buf.push(TAG_OID);
        self.write_length(encoded.len());
        self.buf.extend_from_slice(&encoded);
    }

    fn write_length(&mut self, len: usize) {
        if len < 0x80 {
            self.buf.push(len as u8);
        } else if len <= 0xFF {
            self.buf.push(0x81);
            self.buf.push(len as u8);
        } else if len <= 0xFFFF {
            self.buf.push(0x82);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x83);
            self.buf.push((len >> 16) as u8);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        }
    }
}

fn encode_integer_bytes(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let mut bytes = val.to_be_bytes().to_vec();
    // Strip leading 0x00 or 0xFF that are redundant
    if val > 0 {
        while bytes.len() > 1 && bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
            bytes.remove(0);
        }
    } else {
        while bytes.len() > 1 && bytes[0] == 0xFF && bytes[1] & 0x80 != 0 {
            bytes.remove(0);
        }
    }
    bytes
}

fn encode_oid(oid: &Oid) -> Vec<u8> {
    let c = oid.components();
    if c.len() < 2 {
        return vec![];
    }
    let mut out = vec![(c[0] * 40 + c[1]) as u8];
    for &sub in &c[2..] {
        encode_sub_id(&mut out, sub);
    }
    out
}

fn encode_sub_id(out: &mut Vec<u8>, mut val: u32) {
    if val == 0 {
        out.push(0);
        return;
    }
    let mut tmp = Vec::new();
    while val > 0 {
        tmp.push((val & 0x7F) as u8);
        val >>= 7;
    }
    tmp.reverse();
    for (i, b) in tmp.iter().enumerate() {
        if i < tmp.len() - 1 {
            out.push(b | 0x80);
        } else {
            out.push(*b);
        }
    }
}

// --- Decoder ---

pub struct BerDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BerDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn peek_tag(&self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(SnmpError::Decode("unexpected end of data".into()));
        }
        Ok(self.data[self.pos])
    }

    pub fn read_tag(&mut self) -> Result<u8> {
        let tag = self.peek_tag()?;
        self.pos += 1;
        Ok(tag)
    }

    pub fn read_length(&mut self) -> Result<usize> {
        if self.pos >= self.data.len() {
            return Err(SnmpError::Decode("unexpected end of data".into()));
        }
        let first = self.data[self.pos];
        self.pos += 1;
        if first < 0x80 {
            Ok(first as usize)
        } else {
            let num_bytes = (first & 0x7F) as usize;
            if self.pos + num_bytes > self.data.len() {
                return Err(SnmpError::Decode("length overflow".into()));
            }
            let mut len: usize = 0;
            for i in 0..num_bytes {
                len = (len << 8) | self.data[self.pos + i] as usize;
            }
            self.pos += num_bytes;
            Ok(len)
        }
    }

    pub fn read_raw(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(SnmpError::Decode("data too short".into()));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self.read_tag()?;
        let len = self.read_length()?;
        let data = self.read_raw(len)?;
        Ok((tag, data))
    }

    /// Read a TLV and return the full encoded bytes (tag + length + value).
    pub fn read_tlv_with_header(&mut self) -> Result<(u8, Vec<u8>)> {
        let start = self.pos;
        let tag = self.read_tag()?;
        let len = self.read_length()?;
        let _ = self.read_raw(len)?;
        let end = self.pos;
        let full = self.data[start..end].to_vec();
        Ok((tag, full))
    }

    pub fn read_sequence(&mut self) -> Result<BerDecoder<'a>> {
        let tag = self.read_tag()?;
        if tag != TAG_SEQUENCE {
            return Err(SnmpError::Decode(format!("expected SEQUENCE, got 0x{:02X}", tag)));
        }
        let len = self.read_length()?;
        let data = self.read_raw(len)?;
        Ok(BerDecoder::new(data))
    }

    pub fn read_integer(&mut self) -> Result<i64> {
        let (tag, data) = self.read_tlv()?;
        if tag != TAG_INTEGER {
            return Err(SnmpError::Decode(format!("expected INTEGER, got 0x{:02X}", tag)));
        }
        Ok(decode_integer(data))
    }

    pub fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        let (tag, data) = self.read_tlv()?;
        if tag != TAG_OCTET_STRING {
            return Err(SnmpError::Decode(format!("expected OCTET STRING, got 0x{:02X}", tag)));
        }
        Ok(data)
    }

    pub fn read_oid(&mut self) -> Result<Oid> {
        let (tag, data) = self.read_tlv()?;
        if tag != TAG_OID {
            return Err(SnmpError::Decode(format!("expected OID, got 0x{:02X}", tag)));
        }
        decode_oid(data)
    }

    pub fn read_value(&mut self) -> Result<Value> {
        let (tag, data) = self.read_tlv()?;
        match tag {
            TAG_INTEGER => Ok(Value::Integer(decode_integer(data))),
            TAG_OCTET_STRING => Ok(Value::OctetString(data.to_vec())),
            TAG_NULL => Ok(Value::Null),
            TAG_OID => Ok(Value::ObjectIdentifier(decode_oid(data)?)),
            TAG_IPADDRESS => {
                if data.len() == 4 {
                    Ok(Value::IpAddress([data[0], data[1], data[2], data[3]]))
                } else {
                    Ok(Value::OctetString(data.to_vec()))
                }
            }
            TAG_COUNTER32 => Ok(Value::Counter32(decode_unsigned32(data))),
            TAG_GAUGE32 => Ok(Value::Gauge32(decode_unsigned32(data))),
            TAG_TIMETICKS => Ok(Value::TimeTicks(decode_unsigned32(data))),
            TAG_OPAQUE => Ok(Value::Opaque(data.to_vec())),
            TAG_COUNTER64 => Ok(Value::Counter64(decode_unsigned64(data))),
            TAG_NO_SUCH_OBJECT => Ok(Value::NoSuchObject),
            TAG_NO_SUCH_INSTANCE => Ok(Value::NoSuchInstance),
            TAG_END_OF_MIB_VIEW => Ok(Value::EndOfMibView),
            _ => Ok(Value::OctetString(data.to_vec())),
        }
    }
}

fn decode_integer(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let mut val: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in data {
        val = (val << 8) | b as i64;
    }
    val
}

fn decode_unsigned32(data: &[u8]) -> u32 {
    let mut val: u32 = 0;
    for &b in data {
        val = (val << 8) | b as u32;
    }
    val
}

fn decode_unsigned64(data: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in data {
        val = (val << 8) | b as u64;
    }
    val
}

fn decode_oid(data: &[u8]) -> Result<Oid> {
    if data.is_empty() {
        return Ok(Oid::from_slice(&[]));
    }
    let first = data[0];
    let mut components = vec![(first / 40) as u32, (first % 40) as u32];
    let mut i = 1;
    while i < data.len() {
        let mut sub: u32 = 0;
        loop {
            if i >= data.len() {
                return Err(SnmpError::Decode("truncated OID sub-identifier".into()));
            }
            let b = data[i];
            i += 1;
            sub = (sub << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
        components.push(sub);
    }
    Ok(Oid(components))
}

// --- PDU encoding/decoding ---

/// Encode an SNMPv1/v2c GET request.
pub fn encode_get_request(version: Version, community: &[u8], request_id: i32, oids: &[Oid]) -> Vec<u8> {
    encode_pdu(version, community, request_id, PDU_GET, oids, &[])
}

/// Encode an SNMPv1/v2c GETNEXT request.
pub fn encode_getnext_request(version: Version, community: &[u8], request_id: i32, oids: &[Oid]) -> Vec<u8> {
    encode_pdu(version, community, request_id, PDU_GETNEXT, oids, &[])
}

/// Encode an SNMPv1/v2c GETBULK request.
pub fn encode_getbulk_request(
    version: Version,
    community: &[u8],
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
    oids: &[Oid],
) -> Vec<u8> {
    let varbind_list = encode_varbind_list_null(oids);

    let mut pdu = BerEncoder::new();
    pdu.write_integer(request_id as i64);
    pdu.write_integer(non_repeaters as i64);
    pdu.write_integer(max_repetitions as i64);
    pdu.write_sequence(&varbind_list);
    let pdu_bytes = pdu.into_bytes();

    let mut msg = BerEncoder::new();
    msg.write_integer(version.to_i64());
    msg.write_octet_string(community);
    msg.write_tagged(PDU_GETBULK, &pdu_bytes);
    let msg_bytes = msg.into_bytes();

    let mut out = BerEncoder::new();
    out.write_sequence(&msg_bytes);
    out.into_bytes()
}

/// Encode an SNMPv1/v2c SET request.
pub fn encode_set_request(version: Version, community: &[u8], request_id: i32, varbinds: &[VarBind]) -> Vec<u8> {
    let varbind_list = encode_varbind_list(varbinds);

    let mut pdu = BerEncoder::new();
    pdu.write_integer(request_id as i64);
    pdu.write_integer(0); // error-status
    pdu.write_integer(0); // error-index
    pdu.write_sequence(&varbind_list);
    let pdu_bytes = pdu.into_bytes();

    let mut msg = BerEncoder::new();
    msg.write_integer(version.to_i64());
    msg.write_octet_string(community);
    msg.write_tagged(PDU_SET, &pdu_bytes);
    let msg_bytes = msg.into_bytes();

    let mut out = BerEncoder::new();
    out.write_sequence(&msg_bytes);
    out.into_bytes()
}

fn encode_pdu(version: Version, community: &[u8], request_id: i32, pdu_type: u8, oids: &[Oid], _varbinds: &[VarBind]) -> Vec<u8> {
    let varbind_list = encode_varbind_list_null(oids);

    let mut pdu = BerEncoder::new();
    pdu.write_integer(request_id as i64);
    pdu.write_integer(0); // error-status
    pdu.write_integer(0); // error-index
    pdu.write_sequence(&varbind_list);
    let pdu_bytes = pdu.into_bytes();

    let mut msg = BerEncoder::new();
    msg.write_integer(version.to_i64());
    msg.write_octet_string(community);
    msg.write_tagged(pdu_type, &pdu_bytes);
    let msg_bytes = msg.into_bytes();

    let mut out = BerEncoder::new();
    out.write_sequence(&msg_bytes);
    out.into_bytes()
}

fn encode_varbind_list_null(oids: &[Oid]) -> Vec<u8> {
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

fn encode_varbind_list(varbinds: &[VarBind]) -> Vec<u8> {
    let mut inner = BerEncoder::new();
    for vb in varbinds {
        let mut enc = BerEncoder::new();
        enc.write_oid(&vb.oid);
        encode_value(&mut enc, &vb.value);
        let vb_bytes = enc.into_bytes();
        inner.write_sequence(&vb_bytes);
    }
    inner.into_bytes()
}

fn encode_value(enc: &mut BerEncoder, value: &Value) {
    match value {
        Value::Integer(v) => enc.write_integer(*v),
        Value::OctetString(b) => enc.write_octet_string(b),
        Value::Null => enc.write_null(),
        Value::ObjectIdentifier(oid) => enc.write_oid(oid),
        Value::IpAddress(ip) => enc.write_tagged(TAG_IPADDRESS, ip),
        Value::Counter32(v) => enc.write_tagged(TAG_COUNTER32, &encode_unsigned32(*v)),
        Value::Gauge32(v) => enc.write_tagged(TAG_GAUGE32, &encode_unsigned32(*v)),
        Value::TimeTicks(v) => enc.write_tagged(TAG_TIMETICKS, &encode_unsigned32(*v)),
        Value::Opaque(b) => enc.write_tagged(TAG_OPAQUE, b),
        Value::Counter64(v) => enc.write_tagged(TAG_COUNTER64, &encode_unsigned64(*v)),
        _ => enc.write_null(),
    }
}

fn encode_unsigned32(val: u32) -> Vec<u8> {
    encode_integer_bytes(val as i64)
}

fn encode_unsigned64(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    // Add leading zero if high bit set (to keep it positive)
    if bytes[start] & 0x80 != 0 {
        let mut out = vec![0x00];
        out.extend_from_slice(&bytes[start..]);
        out
    } else {
        bytes[start..].to_vec()
    }
}

/// Decoded SNMP response.
#[derive(Debug)]
pub struct SnmpResponse {
    pub version: Version,
    pub community: Vec<u8>,
    pub request_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Vec<VarBind>,
}

/// Decode an SNMPv1/v2c response message.
pub fn decode_response(data: &[u8]) -> Result<SnmpResponse> {
    let mut dec = BerDecoder::new(data);
    let mut msg = dec.read_sequence()?;

    let ver = msg.read_integer()?;
    let version = match ver {
        0 => Version::V1,
        1 => Version::V2c,
        3 => Version::V3,
        _ => return Err(SnmpError::Decode(format!("unknown version: {}", ver))),
    };

    let community = msg.read_octet_string()?.to_vec();

    // PDU (context-specific constructed)
    let pdu_tag = msg.read_tag()?;
    if pdu_tag != PDU_RESPONSE {
        return Err(SnmpError::Decode(format!("expected Response PDU (0xA2), got 0x{:02X}", pdu_tag)));
    }
    let pdu_len = msg.read_length()?;
    let pdu_data = msg.read_raw(pdu_len)?;
    let mut pdu = BerDecoder::new(pdu_data);

    let request_id = pdu.read_integer()? as i32;
    let error_status = pdu.read_integer()? as u32;
    let error_index = pdu.read_integer()? as u32;

    // VarBind list
    let mut vbl = pdu.read_sequence()?;
    let mut varbinds = Vec::new();
    while vbl.remaining() > 0 {
        let mut vb_dec = vbl.read_sequence()?;
        let oid = vb_dec.read_oid()?;
        let value = vb_dec.read_value()?;
        varbinds.push(VarBind { oid, value });
    }

    Ok(SnmpResponse {
        version,
        community,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}

/// Public wrapper for encoding a Value (used by v3_client).
pub fn encode_value_pub(enc: &mut BerEncoder, value: &Value) {
    encode_value(enc, value);
}
