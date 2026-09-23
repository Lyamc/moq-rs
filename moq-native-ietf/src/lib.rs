// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod quic;
pub mod tls;

/// Install the pure-Rust rustls CryptoProvider (`rustls-rustcrypto`).
///
/// Safe to call multiple times. Call once at process start for binaries that
/// use Quinn / WebTransport / hyper-serve with no-provider rustls.
pub fn install_pure_crypto() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());
}
