use rusnmp::*;
use rusnmp::codec::{encode_get_request, encode_getnext_request, encode_set_request, decode_response};

#[test]
fn test_oid_display() {
    let oid = oid!(1, 3, 6, 1, 2, 1);
    assert_eq!(format!("{}", oid), "1.3.6.1.2.1");
}

#[test]
fn test_oid_equality() {
    let a = oid!(1, 3, 6, 1);
    let b = Oid::from_str("1.3.6.1").unwrap();
    assert_eq!(a, b);
}

#[test]
fn test_oid_from_str_invalid() {
    assert!(Oid::from_str("").is_err());
    assert!(Oid::from_str("abc").is_err());
    assert!(Oid::from_str("1.3.abc.1").is_err());
}

#[test]
fn test_oid_starts_with() {
    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
    let prefix = oid!(1, 3, 6, 1, 2, 1);
    assert!(oid.0.starts_with(&prefix.0));
    assert!(!prefix.0.starts_with(&oid.0));
}

#[test]
fn test_value_display() {
    assert_eq!(format!("{:?}", Value::Integer(42)), "Integer(42)");
    assert_eq!(format!("{:?}", Value::Counter32(100)), "Counter32(100)");
    assert_eq!(format!("{:?}", Value::Null), "Null");
}

#[test]
fn test_value_octet_string() {
    let val = Value::OctetString(b"test string".to_vec());
    assert_eq!(val.as_str(), Some("test string"));
    assert_eq!(val.as_bytes(), Some(b"test string".as_slice()));
    assert_eq!(val.as_i64(), None);
}

#[test]
fn test_value_conversions() {
    assert_eq!(Value::Integer(-1).as_i64(), Some(-1));
    assert_eq!(Value::Counter32(u32::MAX).as_i64(), Some(u32::MAX as i64));
    assert_eq!(Value::Gauge32(0).as_i64(), Some(0));
    assert_eq!(Value::TimeTicks(100).as_i64(), Some(100));
    assert_eq!(Value::Counter64(u64::MAX).as_i64(), Some(u64::MAX as i64));
}

#[test]
fn test_encode_get_request_structure() {
    let oids = vec![oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)];
    let packet = encode_get_request(Version::V2c, b"public", 1, &oids);

    // Must start with SEQUENCE tag
    assert_eq!(packet[0], 0x30);
    // Must contain the community string
    assert!(packet.windows(6).any(|w| w == b"public"));
}

#[test]
fn test_encode_getnext_request_structure() {
    let oids = vec![oid!(1, 3, 6, 1, 2, 1, 2, 2)];
    let packet = encode_getnext_request(Version::V2c, b"private", 99, &oids);

    assert_eq!(packet[0], 0x30);
    assert!(packet.windows(7).any(|w| w == b"private"));
}

#[test]
fn test_encode_set_request_structure() {
    let varbinds = vec![VarBind {
        oid: oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
        value: Value::OctetString(b"newhost".to_vec()),
    }];
    let packet = encode_set_request(Version::V2c, b"private", 42, &varbinds);

    assert_eq!(packet[0], 0x30);
    assert!(packet.windows(7).any(|w| w == b"newhost"));
}

#[test]
fn test_encode_multiple_oids() {
    let oids = vec![
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
    ];
    let packet = encode_get_request(Version::V1, b"public", 5, &oids);
    assert_eq!(packet[0], 0x30);
    assert!(packet.len() > 40); // Should be larger with 3 OIDs
}

#[test]
fn test_version_encoding() {
    let oids = vec![oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)];

    let v1_packet = encode_get_request(Version::V1, b"public", 1, &oids);
    let v2c_packet = encode_get_request(Version::V2c, b"public", 1, &oids);

    // V1 has version=0, V2c has version=1 in the BER encoding
    // Both should be valid packets but differ in version field
    assert_ne!(v1_packet, v2c_packet);
}

#[test]
fn test_decode_response_invalid() {
    // Empty data
    assert!(decode_response(&[]).is_err());
    // Random garbage
    assert!(decode_response(&[0xFF, 0x01, 0x02]).is_err());
    // Too short
    assert!(decode_response(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
}

#[cfg(feature = "v3")]
mod v3_tests {
    use rusnmp::v3::{UsmCredentials, AuthProtocol, PrivProtocol, password_to_key};

    #[test]
    fn test_usm_no_auth() {
        let creds = UsmCredentials::no_auth("readonly");
        assert_eq!(creds.security_level(), 0x00);
    }

    #[test]
    fn test_usm_auth_only() {
        let creds = UsmCredentials::auth_only("admin", AuthProtocol::Md5, "password");
        assert_eq!(creds.security_level(), 0x01);
    }

    #[test]
    fn test_usm_auth_priv() {
        let creds = UsmCredentials::auth_priv(
            "admin", AuthProtocol::Sha256, "authpass",
            PrivProtocol::Aes128, "privpass",
        );
        assert_eq!(creds.security_level(), 0x03);
    }

    #[test]
    fn test_password_to_key_lengths() {
        let engine_id = b"\x80\x00\x00\x01\x02";

        let md5_key = password_to_key(AuthProtocol::Md5, b"testpass", engine_id);
        assert_eq!(md5_key.len(), 16);

        let sha1_key = password_to_key(AuthProtocol::Sha1, b"testpass", engine_id);
        assert_eq!(sha1_key.len(), 20);

        let sha256_key = password_to_key(AuthProtocol::Sha256, b"testpass", engine_id);
        assert_eq!(sha256_key.len(), 32);
    }

    #[test]
    fn test_password_to_key_deterministic() {
        let engine_id = b"\x01\x02\x03\x04\x05";
        let k1 = password_to_key(AuthProtocol::Sha1, b"secret", engine_id);
        let k2 = password_to_key(AuthProtocol::Sha1, b"secret", engine_id);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_password_to_key_different_passwords() {
        let engine_id = b"\x01\x02\x03";
        let k1 = password_to_key(AuthProtocol::Sha1, b"pass1", engine_id);
        let k2 = password_to_key(AuthProtocol::Sha1, b"pass2", engine_id);
        assert_ne!(k1, k2);
    }
}
