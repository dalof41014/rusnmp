# rusnmp

[![Crates.io](https://img.shields.io/crates/v/rusnmp.svg)](https://crates.io/crates/rusnmp)
[![Docs.rs](https://docs.rs/rusnmp/badge.svg)](https://docs.rs/rusnmp)
[![License](https://img.shields.io/crates/l/rusnmp.svg)](https://github.com/dalof41014/rusnmp/blob/main/LICENSE-MIT)

**`rusnmp`** is a lightweight, async SNMP v1/v2c client library for Rust built on Tokio with minimal dependencies.

---

## Features

* ✅ Async UDP transport (Tokio)
* ✅ SNMPv1 and SNMPv2c support
* ✅ GET, GETNEXT, GETBULK, SET operations
* ✅ SNMP Walk (auto GETNEXT/GETBULK)
* ✅ Pure Rust BER encoder/decoder
* ✅ Typed values (Integer, OctetString, Counter32/64, Gauge32, TimeTicks, IpAddress, OID)
* ✅ `oid!` macro for compile-time OID construction
* ✅ Configurable timeout
* ✅ Minimal dependencies — no C bindings, no libnetsnmp
* 🚧 SNMPv3 USM (optional `v3` feature, coming soon)

---

## Quick Start

```toml
[dependencies]
rusnmp = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

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

---

## API Summary

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

## OID Macro

```rust
use rusnmp::oid;

let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
let if_table = oid!(1, 3, 6, 1, 2, 1, 2, 2);
```

You can also parse from strings:

```rust
use rusnmp::Oid;

let oid = Oid::from_str("1.3.6.1.2.1.1.1.0").unwrap();
```

---

## Dependencies

Minimal by design:

```toml
tokio = "1"       # async runtime
thiserror = "1"   # error types
log = "0.4"       # logging
rand = "0.8"      # request IDs
```

SNMPv3 crypto (optional, enabled by default via `v3` feature):
`hmac`, `sha1`, `sha2`, `md-5`, `aes`, `cbc`, `cfb-mode`, `des`

To use without v3 crypto:
```toml
rusnmp = { version = "0.1", default-features = false }
```

---

## License

MIT OR Apache-2.0
