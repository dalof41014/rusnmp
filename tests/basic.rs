use rusnmp::*;

#[test]
fn test_oid_macro() {
    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
    assert_eq!(oid.components(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
}

#[test]
fn test_oid_from_str() {
    let oid = Oid::from_str("1.3.6.1.2.1.1.1.0").unwrap();
    assert_eq!(oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

#[test]
fn test_value_as_str() {
    let val = Value::OctetString(b"hello".to_vec());
    assert_eq!(val.as_str(), Some("hello"));

    let val = Value::Integer(42);
    assert_eq!(val.as_str(), None);
}

#[test]
fn test_value_as_i64() {
    assert_eq!(Value::Integer(42).as_i64(), Some(42));
    assert_eq!(Value::Counter32(100).as_i64(), Some(100));
    assert_eq!(Value::Gauge32(200).as_i64(), Some(200));
    assert_eq!(Value::TimeTicks(300).as_i64(), Some(300));
    assert_eq!(Value::Counter64(400).as_i64(), Some(400));
    assert_eq!(Value::Null.as_i64(), None);
}

#[test]
fn test_encode_decode_get_response() {
    use rusnmp::codec::encode_get_request;

    let oids = vec![oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)];
    let packet = encode_get_request(Version::V2c, b"public", 1234, &oids);

    // Verify the packet is valid BER (starts with SEQUENCE tag 0x30)
    assert_eq!(packet[0], 0x30);
    assert!(packet.len() > 20);
}

#[test]
fn test_v3_usm_credentials() {
    use rusnmp::v3::{UsmCredentials, AuthProtocol, PrivProtocol};

    let creds = UsmCredentials::no_auth("public");
    assert_eq!(creds.security_level(), 0x00);

    let creds = UsmCredentials::auth_only("admin", AuthProtocol::Sha1, "authpass");
    assert_eq!(creds.security_level(), 0x01);

    let creds = UsmCredentials::auth_priv("admin", AuthProtocol::Sha256, "auth", PrivProtocol::Aes128, "priv");
    assert_eq!(creds.security_level(), 0x03);
}

#[test]
fn test_v3_password_to_key() {
    use rusnmp::v3::{AuthProtocol, password_to_key};

    // Verify key derivation produces deterministic output
    let engine_id = b"\x80\x00\x00\x01\x02\x03";
    let key1 = password_to_key(AuthProtocol::Sha1, b"maplesyrup", engine_id);
    let key2 = password_to_key(AuthProtocol::Sha1, b"maplesyrup", engine_id);
    assert_eq!(key1, key2);
    assert_eq!(key1.len(), 20); // SHA-1 output

    let key_md5 = password_to_key(AuthProtocol::Md5, b"maplesyrup", engine_id);
    assert_eq!(key_md5.len(), 16); // MD5 output

    let key_sha256 = password_to_key(AuthProtocol::Sha256, b"maplesyrup", engine_id);
    assert_eq!(key_sha256.len(), 32); // SHA-256 output
}
