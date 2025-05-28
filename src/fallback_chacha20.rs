// Copyright 2025 sh0rch <sh0rch@iwl.dev>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Fallback ChaCha20 Implementation (Pure Rust)
//!
//! This module provides a minimal, dependency-free implementation of the ChaCha20
//! stream cipher. It is intended as a fallback when hardware-accelerated or
//! optimized versions are unavailable. The implementation is based on the
//! original ChaCha20 specification and operates on 256-bit keys and 96-bit nonces.
//!
//! ## Usage
//!
//! The main function is [`xor`], which applies the ChaCha20 keystream to a buffer
//! in-place for encryption or decryption. The function expects a 256-bit key and
//! a 128-bit counter/nonce (as four `u32` words).
//!
//! ## Example
//!
//! ```rust
//! use fast_chacha::fallback_chacha20::xor;
//! let key = [0u32; 8];
//! let counter = [0u32; 4];
//! let mut data = [0u8; 64];
//! xor(&mut data, &key, &counter);
//! ```
//!
//! # Security
//!
//! This implementation is intended for fallback or testing purposes. For
//! production use, prefer well-audited and hardware-accelerated libraries.

const DOUBLE_ROUNDS: usize = 10;

/// Performs a single ChaCha20 quarter round operation on the cipher state.
///
/// The quarter round is the core operation of the ChaCha20 algorithm. It mixes
/// four 32-bit words of the state using addition, XOR, and bit rotation. This
/// function is called multiple times per block to provide diffusion.
///
/// # Arguments
/// * `state` - Mutable reference to the cipher state array (16 words).
/// * `a`, `b`, `c`, `d` - Indices of the state words to operate on.
///
/// # Panics
/// Panics if any index is out of bounds for the state array.
#[inline(always)]
fn quarter_round(state: &mut [u32], a: usize, b: usize, c: usize, d: usize) {
    // Add, XOR, and rotate operations as specified by ChaCha20
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// XORs the given data in-place with a ChaCha20 keystream generated from the provided key and counter.
///
/// This function generates a single ChaCha20 block (64 bytes) using the provided key and counter,
/// and XORs it with the input data buffer. The buffer can be up to 64 bytes in length. This function
/// can be used for both encryption and decryption, as ChaCha20 is a symmetric stream cipher.
///
/// # Arguments
/// * `data` - Mutable byte slice to encrypt or decrypt (up to 64 bytes).
/// * `key` - Reference to an array of 8 u32 words (256-bit key).
/// * `counter` - Reference to an array of 4 u32 words (block counter and nonce).
///
/// # Panics
/// Panics if `data` is longer than 64 bytes.
///
/// # Example
/// ```rust
/// use fast_chacha::fallback_chacha20::xor;
/// let key = [0u32; 8];
/// let counter = [0u32; 4];
/// let mut data = [0u8; 64];
/// xor(&mut data, &key, &counter);
/// ```
pub fn xor(data: &mut [u8], key: &[u32], counter: &[u32]) {
    assert!(data.len() <= 64, "Data length must not exceed 64 bytes");
    let mut state = [0u32; 16];
    // ChaCha20 constants ("expand 32-byte k")
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key: 8 words (32 bytes)
    state[4..(8 + 4)].copy_from_slice(key);
    // Counter and nonce: 4 words
    state[12..].copy_from_slice(counter);

    // Copy state for working
    let mut working_state = state;
    // 20 rounds (10 double rounds)
    for _ in 0..DOUBLE_ROUNDS {
        // Column rounds
        quarter_round(&mut working_state, 0, 4, 8, 12);
        quarter_round(&mut working_state, 1, 5, 9, 13);
        quarter_round(&mut working_state, 2, 6, 10, 14);
        quarter_round(&mut working_state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working_state, 0, 5, 10, 15);
        quarter_round(&mut working_state, 1, 6, 11, 12);
        quarter_round(&mut working_state, 2, 7, 8, 13);
        quarter_round(&mut working_state, 3, 4, 9, 14);
    }
    // Add original state to working state
    for (w, s) in working_state.iter_mut().zip(state.iter()) {
        *w = w.wrapping_add(*s);
    }
    // Serialize keystream block to bytes
    let mut block = [0u8; 64];
    for (i, word) in working_state.iter().enumerate() {
        block[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    // XOR keystream with data
    for (b, k) in data.iter_mut().zip(block.iter()) {
        *b ^= *k;
    }
}

#[cfg(test)]
mod tests {
    use crate::fallback_chacha20::xor;

    /// Tests that encrypting and then decrypting with the same key and counter
    /// returns the original plaintext, and that the ciphertext differs from the plaintext.
    #[test]
    fn test_chacha20_xor_encrypt_decrypt() {
        // Example key and nonce (all zeros for simplicity)
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        // Convert key to u32 words
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        // Counter: 4 words, first is 0, next 3 from nonce
        let mut counter = [0u32; 4];
        for i in 0..3 {
            counter[i + 1] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        // Plaintext to encrypt
        let plaintext = b"Hello, ChaCha20 fallback test!";
        let mut buffer = [0u8; 32];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        // Encrypt in place
        xor(&mut buffer[..plaintext.len()], &key_words, &counter);

        // Save ciphertext for assertion
        let mut ciphertext = [0u8; 64];
        ciphertext[..plaintext.len()].copy_from_slice(&buffer[..plaintext.len()]);

        // Decrypt in place
        xor(&mut buffer[..plaintext.len()], &key_words, &counter);

        // Check that decryption yields the original plaintext
        assert_eq!(&buffer[..plaintext.len()], plaintext);

        // Check that ciphertext is not equal to plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
    }
}
