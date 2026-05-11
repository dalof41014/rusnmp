//! # rusnmp
//!
//! A lightweight, async SNMP v1/v2c/v3 client library for Rust.
//!
//! ## Quick Start
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

mod client;
pub mod codec;
mod error;
mod types;

pub use client::SnmpClient;
pub use error::{SnmpError, Result};
pub use types::*;
