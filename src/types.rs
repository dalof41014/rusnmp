use std::fmt;

/// An SNMP Object Identifier (OID).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    pub fn from_slice(components: &[u32]) -> Self {
        Self(components.to_vec())
    }

    /// Parse dotted string like "1.3.6.1.2.1.1.1.0"
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> std::result::Result<Self, &'static str> {
        let parts: std::result::Result<Vec<u32>, _> = s
            .trim_start_matches('.')
            .split('.')
            .map(|p| p.parse::<u32>())
            .collect();
        parts.map(Oid).map_err(|_| "invalid OID string")
    }

    pub fn components(&self) -> &[u32] {
        &self.0
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.0.iter().map(|c| c.to_string()).collect();
        write!(f, "{}", s.join("."))
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self)
    }
}

/// SNMP value types.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Oid),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    /// Try to interpret as a UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::OctetString(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    /// Try to get as integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(v) => Some(*v),
            Value::Counter32(v) => Some(*v as i64),
            Value::Gauge32(v) => Some(*v as i64),
            Value::TimeTicks(v) => Some(*v as i64),
            Value::Counter64(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Try to get as bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::OctetString(b) | Value::Opaque(b) => Some(b),
            _ => None,
        }
    }
}

/// A variable binding (OID + value pair).
#[derive(Debug, Clone)]
pub struct VarBind {
    pub oid: Oid,
    pub value: Value,
}

/// SNMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2c,
    V3,
}

impl Version {
    pub fn to_i64(self) -> i64 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
            Version::V3 => 3,
        }
    }
}

/// Macro to create an OID from literal components.
#[macro_export]
macro_rules! oid {
    ($($c:expr),+ $(,)?) => {
        $crate::Oid::from_slice(&[$($c),+])
    };
}
