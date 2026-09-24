# Pure-Rust MoQ (no `ring` / no `cc` / no Windows `libc`)

This fork builds the **full default workspace** without `ring`, without the `cc` crate, and without the `libc` crate on Windows.

`cargo tree -i libc` and `cargo tree -i cc` are empty for `x86_64-pc-windows-msvc`. `cargo tree -i cc --target all` is empty. `cargo tree -i ring` is empty.

Unix, Apple, and Android targets still link the `libc` crate through Tokio, Mio, socket2, and the Unix half of `quinn-udp` from [Lyamc/quinn](https://github.com/Lyamc/quinn) (ancillary UDP data). Those calls are real socket ABI, not a Windows type alias.

The legacy rustls fork at `C:\Build\rustls-lyamc` is for TLS 1.2 static RSA and CBC. It is not used here. Stock rustls 0.23 with `default-features = false` does not pull `libc` or `cc`. Crypto is `vendor/rustls-rustcrypto` (same role as Graviola: a pure-Rust `CryptoProvider`). Graviola is not required.

## Verify

```bash
cargo tree -i libc --target x86_64-pc-windows-msvc -e normal,build   # empty
cargo tree -i cc --target all -e normal,build                        # empty
cargo tree -i ring --target all -e normal,build                      # empty
cargo check --workspace
cargo test -p moq-native-ietf --test pure_quic_smoke
cargo test -p moq-clock-ietf --bin moq-clock-ietf unix_epoch_and_known_instants
```

Smoke tests (`moq-native-ietf/tests/pure_quic_smoke.rs`):

| Test | What it proves |
|------|----------------|
| `pure_provider_has_quic_initial_suite` | rustls-rustcrypto exposes AES-128-GCM QUIC |
| `pure_fingerprint_is_sha256_hex` | TLS load / fingerprints without ring |
| `pure_webtransport_handshake` | Client ↔ server WT over pure Quinn |
| `pure_webtransport_bidi_stream_echo` | Bidirectional stream I/O |
| `pure_webtransport_datagram_echo` | Datagram I/O |

## How pure TLS works

rustls **0.23** defaults pull **aws-lc-rs** (C). Feature `ring` pulls **ring** (also C via `cc`).

Pure path:

```toml
rustls = { version = "0.23", default-features = false, features = ["std", "tls12", "logging"] }
```

Then install a process-wide provider:

```rust
moq_native_ietf::install_pure_crypto(); // rustls-rustcrypto
```

### hyper-serve

Vendored `vendor/hyper-serve` is **fixed** for modern hyper-util by requiring `Body::Data: Buf` on `SendService` / `MakeService` (plus pure rustls pins: `default-features = false`).

`moq-relay-ietf` still uses **axum + tokio-rustls** for the fingerprint HTTPS server (simpler stack). hyper-serve remains available for consumers who prefer it:

```bash
cargo check -p hyper-serve   # pure: no ring / no cc
```

## Workspace members (all pure)

| Crate | Role |
|-------|------|
| `moq-native-ietf` | Quinn / WebTransport endpoints |
| `moq-transport` | MoQ protocol |
| `moq-pub` / `moq-sub` | Publish / subscribe |
| `moq-catalog` | Catalog |
| `moq-clock-ietf` | Clock demo |
| `moq-test-client` | Interop client |
| `moq-relay-ietf` | Relay + pure HTTPS fingerprint |
| `moq-api` | API (reqwest no-provider + pure redis rustls) |

## Vendored stack

| Path | Notes |
|------|--------|
| `vendor/rustls-rustcrypto` | Pure CryptoProvider + QUIC AES-128-GCM |
| [Lyamc/quinn](https://github.com/Lyamc/quinn) `a201190d` | Quinn 0.12 with `rustls-pure`. Windows `quinn-udp` uses `std::ffi` instead of the `libc` crate. |
| `vendor/web-transport-quinn` | Feature `pure`, depends on that Quinn revision |
| `vendor/web-transport` | Uses pure WT-Quinn |

## Usage

```rust
// Once per process, before any TLS/QUIC:
moq_native_ietf::install_pure_crypto();
```
