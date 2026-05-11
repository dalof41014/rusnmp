use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnmpError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("BER encoding error: {0}")]
    Encode(String),

    #[error("BER decoding error: {0}")]
    Decode(String),

    #[error("SNMP error: status={status}, index={index}")]
    Snmp { status: u32, index: u32 },

    #[error("USM authentication failed")]
    AuthFailed,

    #[error("USM decryption failed")]
    DecryptFailed,

    #[error("Engine discovery failed")]
    DiscoveryFailed,
}

pub type Result<T> = std::result::Result<T, SnmpError>;
