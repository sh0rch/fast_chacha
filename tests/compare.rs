/*
 * Copyright 2025 sh0rch <sh0rch@iwl.dev>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*!
 * # fast_chacha vs chacha20 Comparison Test
 *
 * This module provides a test that compares the output and performance of the
 * `fast_chacha` implementation (both ASM and fallback backends) against the
 * reference `chacha20` implementation from RustCrypto.
 *
 * The test ensures compatibility (identical output) and prints timing
 * information for each implementation.
 */

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use fast_chacha::FastChaCha20;
use rand::RngCore;

#[cfg(feature = "std")]
use std::time::Instant;

/// Compares the output and performance of RustCrypto's chacha20 implementation
/// with both the ASM-accelerated and fallback implementations of fast_chacha.
///
/// Steps performed by this test:
/// 1. Generates a random key, nonce, and plaintext.
/// 2. Encrypts the plaintext using:
///    - RustCrypto's chacha20
///    - fast_chacha with ASM backend (if available)
///    - fast_chacha with fallback backend
/// 3. Compares the ciphertexts to ensure compatibility.
/// 4. Prints timing information for each implementation.
/// 5. Decrypts the data using fast_chacha and checks that it matches the original plaintext.
#[test]
fn compare_chacha20_vs_fast_chacha() {
    let use_asm = fast_chacha::is_asm_available();

    // Initialize random number generator
    let mut rng = rand::rng();

    // Generate random 256-bit key and 96-bit nonce
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);

    // Generate random plaintext (1 MiB)
    let mut plain = Box::new([0u8; 1024 * 1024]);
    rng.fill_bytes(&mut plain[..]);

    // Prepare buffers for each implementation
    let mut data_std = plain.clone();
    let mut data_fast = plain.clone();
    let mut data_fallback = plain.clone();

    // Encrypt with RustCrypto's chacha20
    #[cfg(feature = "std")]
    let start = Instant::now();

    let mut std_cipher = chacha20::ChaCha20::new((&key).into(), (&nonce).into());
    std_cipher.seek(64);
    std_cipher.apply_keystream(&mut data_std[..]);

    #[cfg(feature = "std")]
    let std_time = start.elapsed();

    // Encrypt with fast_chacha (ASM backend if available)
    #[cfg(feature = "std")]
    let start = Instant::now();

    let mut fast_cipher = FastChaCha20::new(&key, &nonce);
    fast_cipher.seek(64);

    if use_asm {
        fast_cipher.apply_keystream(&mut data_fast[..]);
    } else {
        fast_cipher.apply_keystream_pure(&mut data_fast[..]);
    }

    #[cfg(feature = "std")]
    let fast_time = start.elapsed();

    // Encrypt with fast_chacha (pure fallback backend)
    #[cfg(feature = "std")]
    let start = Instant::now();

    let mut fallback_cipher = FastChaCha20::new(&key, &nonce);
    fallback_cipher.seek(64);
    fallback_cipher.apply_keystream_pure(&mut data_fallback[..]);

    #[cfg(feature = "std")]
    {
        let fallback_time = start.elapsed();

        println!("chacha20 (RustCrypto)\t: {:?}", std_time);
        println!("fast_chacha ({:?})\t: {:?}", if use_asm { "ASM" } else { "Fallback" }, fast_time);
        println!("fast_chacha (Fallback)\t: {:?}", fallback_time);
    }
    // Check that all outputs are identical (compatibility check)
    assert!(
        data_std[..] == data_fast[..],
        "Result data (Fast vs RustCrypto) is not equal. Algorithms are not compatible."
    );

    assert!(
        data_std[..] == data_fallback[..],
        "Result data (Fallback vs RustCrypto) is not equal. Algorithms are not compatible."
    );

    assert!(
        data_fallback[..] == data_fast[..],
        "Result data (Fallback vs Fast) is not equal. Algorithms are not compatible."
    );

    // Decrypt with fast_chacha and verify the result matches the original plaintext
    let mut fast_cipher_dec = FastChaCha20::new(&key, &nonce);
    fast_cipher_dec.seek(64);
    if use_asm {
        fast_cipher_dec.apply_keystream(&mut data_fast[..]);
    } else {
        fast_cipher_dec.apply_keystream_pure(&mut data_fast[..]);
    }
    assert!(data_fast[..] == plain[..], "Decrypted data is not equal to original data.");
}
