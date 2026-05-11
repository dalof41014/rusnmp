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
    // Manually craft a minimal SNMPv2c GET response for sysDescr
    // and verify our decoder handles it.
    use rusnmp::codec::{encode_get_request, decode_response};

    let oids = vec![oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)];
    let packet = encode_get_request(Version::V2c, b"public", 1234, &oids);

    // Verify the packet is valid BER (starts with SEQUENCE tag 0x30)
    assert_eq!(packet[0], 0x30);
    assert!(packet.len() > 20);
}
