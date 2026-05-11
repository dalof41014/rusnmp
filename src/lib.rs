//! # rusnmp
//!
//! A lightweight, async SNMP v1/v2c/v3 client library for Rust.
//!
//! ## Quick Start (v2c)
//!
//! ```no_run
//! use rusnmp::{SnmpClient, oid};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = SnmpClient::new("192.168.1.1", "public").await?;
//!
//!     // GET sysDescr
//!     let result = client.get_one(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.value.as_str());
//!
//!     // Walk ifTable
//!     let entries = client.walk(&oid!(1, 3, 6, 1, 2, 1, 2, 2)).await?;
//!     for vb in entries {
//!         println!("{}: {:?}", vb.oid, vb.value);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## SNMPv3 with USM
//!
//! ```no_run
//! use rusnmp::{SnmpV3Client, oid};
//! use rusnmp::v3::{UsmCredentials, AuthProtocol, PrivProtocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let creds = UsmCredentials::auth_priv(
//!         "admin", AuthProtocol::Sha1, "authpass123",
//!         PrivProtocol::Aes128, "privpass123",
//!     );
//!     let mut client = SnmpV3Client::new("192.168.1.1", creds).await?;
//!
//!     let result = client.get_one(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.value.as_str());
//!     Ok(())
//! }
//! ```
//!
//! ## Trap Receiver
//!
//! ```no_run
//! use rusnmp::TrapReceiver;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let receiver = TrapReceiver::bind("0.0.0.0:162").await?;
//!     loop {
//!         let trap = receiver.recv().await?;
//!         println!("Trap from {}: {:?}", trap.source, trap.varbinds);
//!     }
//! }
//! ```

mod client;
pub mod codec;
mod error;
mod trap;
mod types;
#[cfg(feature = "v3")]
pub mod v3;
#[cfg(feature = "v3")]
mod v3_client;

pub use client::SnmpClient;
pub use error::{SnmpError, Result};
pub use trap::{Trap, TrapReceiver};
pub use types::*;
#[cfg(feature = "v3")]
pub use v3_client::SnmpV3Client;
