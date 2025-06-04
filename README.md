# fast_chacha

[![Crates.io](https://img.shields.io/crates/v/fast_chacha.svg)](https://crates.io/crates/fast_chacha) [![docs.rs](https://docs.rs/fast_chacha/badge.svg)](https://docs.rs/fast_chacha) [![License: Apache-2.0](https://img.shields.io/crates/l/fast_chacha.svg)](LICENSE) [![TESTS](https://github.com/sh0rch/fast_chacha/actions/workflows/tests.yml/badge.svg)](https://github.com/sh0rch/fast_chacha/actions)

High-performance ChaCha20 stream cipher implementation with optional assembly acceleration (leveraging OpenSSL's assembler modules) and pure Rust fallback.

---

## Features

- **OpenSSL Assembly Modules**: Integrates optimized assembly routines sourced from OpenSSL for top-tier performance.
- **Pure Rust Fallback**: Portable implementation when assembly is not supported on the target.
- **Runtime CPU Detection**: Automatically selects the fastest backend at runtime.
- **`no_std` Support**: Works in embedded and bare-metal environments (disable default `std`).

---

## Installation

Add `fast_chacha` to your `Cargo.toml`:

```toml
[dependencies]
fast_chacha = "0.1.0"
```

By default, the `std` feature is enabled. To use in `no_std` environments:

```toml
[dependencies]
fast_chacha = { version = "0.1.0", default-features = false }
```

---

## Usage

Basic example:

```rust
use fast_chacha::FastChaCha20;

let key = [0u8; 32];
let nonce = [0u8; 12];
let mut data = b"Secret message!".to_vec();

// Encrypt or decrypt in-place
let mut cipher = FastChaCha20::new(&key, &nonce);
cipher.apply_keystream(&mut data);
```

If you need to force the pure Rust fallback implementation:

```rust
let mut data = b"Secret message!".to_vec();
let mut cipher = FastChaCha20::new(&key, &nonce);
cipher.apply_keystream_pure(&mut data);
```

---

## API Documentation

Full documentation is available on [docs.rs](https://docs.rs/fast_chacha):

- [`FastChaCha20`](https://docs.rs/fast_chacha/latest/fast_chacha/struct.FastChaCha20.html)
- [`apply_keystream`](https://docs.rs/fast_chacha/latest/fast_chacha/struct.FastChaCha20.html#method.apply_keystream)
- [`apply_keystream_pure`](https://docs.rs/fast_chacha/latest/fast_chacha/struct.FastChaCha20.html#method.apply_keystream_pure)

---

## Build & Assembly Acceleration

The build script (`build.rs`) will compile and link optimized assembly implementations when available. This crate integrates assembly modules directly from OpenSSL, ensuring battle-tested, platform-specific routines. If no assembly is detected for your architecture, the crate falls back to the pure Rust version and emits a warning:

```
cargo:warning=fast_chacha: no ASM for <target>
```

Conditional compilation flag `fast_chacha_asm` is enabled when assembly (from OpenSSL) is used.

---

## Benchmark

Here is a sample result of the comparison test for encrypting a 1 MiB block:

```text
chacha20 (RustCrypto)   : 111.8584ms
fast_chacha ("ASM")     : 547.7µs
fast_chacha (Fallback)  : 14.6214ms
chacha6 (Fallback)      : 9.4224ms
```

Actual results of tests you can see on [Github Actions page](https://github.com/sh0rch/fast_chacha/actions/workflows/tests.yml).

- **fast_chacha ("ASM")** is significantly faster than both the pure Rust fallback and the reference RustCrypto implementation.
- The pure Rust fallback is also noticeably faster than RustCrypto's chacha20.

> _Note: Actual performance may vary depending on your CPU and platform._

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE) © 2025 sh0rch [sh0rch@iwl.dev](mailto:sh0rch@iwl.dev)

---

## Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or pull request on GitHub:

[https://github.com/sh0rch/fast_chacha](https://github.com/sh0rch/fast_chacha)

---

## Acknowledgements

Based on the original [ChaCha20 specification (RFC 8439)](https://tools.ietf.org/html/rfc8439) and assembly modules from [OpenSSL](https://www.openssl.org/).
