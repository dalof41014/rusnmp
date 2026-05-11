# rusnmp

[![Crates.io](https://img.shields.io/crates/v/rusnmp.svg)](https://crates.io/crates/rusnmp)
[![Docs.rs](https://docs.rs/rusnmp/badge.svg)](https://docs.rs/rusnmp)
[![License](https://img.shields.io/crates/l/rusnmp.svg)](https://github.com/dalof41014/rusnmp/blob/main/LICENSE-MIT)

**`rusnmp`** is a lightweight, async SNMP v1/v2c/v3 client library for Rust built on Tokio with minimal dependencies.

---

## Features

* ✅ Async UDP transport (Tokio)
* ✅ SNMPv1 and SNMPv2c support
* ✅ SNMPv3 with USM (User-based Security Model)
  * Authentication: MD5, SHA-1, SHA-256
  * Privacy: DES, AES-128
  * Automatic engine discovery (RFC 3414)
  * Key localization
* ✅ GET, GETNEXT, GETBULK, SET operations
* ✅ SNMP Walk (auto GETNEXT/GETBULK)
* ✅ Trap receiver (v1/v2c/v3)
* ✅ Pure Rust BER encoder/decoder
* ✅ Typed values (Integer, OctetString, Counter32/64, Gauge32, TimeTicks, IpAddress, OID)
* ✅ `oid!` macro for compile-time OID construction
* ✅ Configurable timeout
* ✅ Minimal dependencies — no C bindings, no libnetsnmp

---

## Quick Start

```toml
[dependencies]
rusnmp = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

### SNMPv2c

```rust
use rusnmp::{SnmpClient, oid};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SnmpClient::new("192.168.1.1", "public").await?;

    // GET sysDescr.0
    let result = client.get_one(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {}", result.value.as_str().unwrap_or("N/A"));

    // GET multiple OIDs
    let results = client.get(&[
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),  // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),  // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),  // sysName
    ]).await?;
    for vb in &results {
        println!("{}: {:?}", vb.oid, vb.value);
    }

    // Walk ifTable
    let entries = client.walk(&oid!(1, 3, 6, 1, 2, 1, 2, 2)).await?;
    for vb in entries {
        println!("{}: {:?}", vb.oid, vb.value);
    }

    Ok(())
}
```

### SNMPv3 (USM)

```rust
use rusnmp::{SnmpV3Client, oid};
use rusnmp::v3::{UsmCredentials, AuthProtocol, PrivProtocol};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // AuthPriv: SHA-1 authentication + AES-128 encryption
    let creds = UsmCredentials::auth_priv(
        "admin",
        AuthProtocol::Sha1, "authpass123",
        PrivProtocol::Aes128, "privpass123",
    );
    let mut client = SnmpV3Client::new("192.168.1.1", creds).await?;

    let result = client.get_one(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.value.as_str());

    // Walk also works with v3
    let entries = client.walk(&oid!(1, 3, 6, 1, 2, 1, 2, 2)).await?;
    for vb in entries {
        println!("{}: {:?}", vb.oid, vb.value);
    }

    Ok(())
}
```

### Trap Receiver

```rust
use rusnmp::TrapReceiver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let receiver = TrapReceiver::bind("0.0.0.0:162").await?;
    println!("Listening for traps on port 162...");

    loop {
        let trap = receiver.recv().await?;
        println!("Trap from {}: version={:?}", trap.source, trap.version);
        for vb in &trap.varbinds {
            println!("  {}: {:?}", vb.oid, vb.value);
        }
    }
}
```

---

## API Summary

### SnmpClient (v1/v2c)

| Method | Description |
|--------|-------------|
| `SnmpClient::new(target, community)` | Create v2c client (default port 161) |
| `SnmpClient::with_version(target, community, version)` | Create client with specific version |
| `set_timeout(duration)` | Set request timeout |
| `get(oids)` | GET one or more OIDs |
| `get_one(oid)` | GET a single OID (convenience) |
| `get_next(oids)` | GETNEXT operation |
| `get_bulk(oids, non_repeaters, max_repetitions)` | GETBULK (v2c) |
| `set(varbinds)` | SET operation |
| `walk(root_oid)` | Walk subtree (auto GETNEXT/GETBULK) |

### SnmpV3Client (USM)

| Method | Description |
|--------|-------------|
| `SnmpV3Client::new(target, credentials)` | Create v3 client (auto engine discovery) |
| `set_timeout(duration)` | Set request timeout |
| `get(oids)` | GET one or more OIDs |
| `get_one(oid)` | GET a single OID |
| `get_next(oids)` | GETNEXT operation |
| `get_bulk(oids, non_repeaters, max_repetitions)` | GETBULK |
| `set(varbinds)` | SET operation |
| `walk(root_oid)` | Walk subtree |

### TrapReceiver

| Method | Description |
|--------|-------------|
| `TrapReceiver::bind(addr)` | Bind trap listener (e.g. "0.0.0.0:162") |
| `recv()` | Receive next trap (async) |

### USM Security Levels

| Constructor | Auth | Priv |
|-------------|------|------|
| `UsmCredentials::no_auth(user)` | ✗ | ✗ |
| `UsmCredentials::auth_only(user, proto, pass)` | ✓ | ✗ |
| `UsmCredentials::auth_priv(user, auth_proto, auth_pass, priv_proto, priv_pass)` | ✓ | ✓ |

---

## Value Types

| Variant | Rust Type |
|---------|-----------|
| `Value::Integer` | `i64` |
| `Value::OctetString` | `Vec<u8>` |
| `Value::ObjectIdentifier` | `Oid` |
| `Value::IpAddress` | `[u8; 4]` |
| `Value::Counter32` | `u32` |
| `Value::Gauge32` | `u32` |
| `Value::TimeTicks` | `u32` |
| `Value::Counter64` | `u64` |
| `Value::Null` | — |

---

## Dependencies

Core (always required):
```
tokio, thiserror, log, rand
```

SNMPv3 crypto (optional `v3` feature, enabled by default):
```
hmac, sha1, sha2, md-5, aes, cbc, cfb-mode, des, block-padding
```

To use without v3:
```toml
rusnmp = { version = "0.1", default-features = false }
```

---

## License

MIT OR Apache-2.0
