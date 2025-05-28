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

//! FastChaCha20: High-performance ChaCha20 stream cipher implementation with optional assembly optimizations.
//!
//! This module provides a ChaCha20 implementation that can use optimized assembly routines if available,
//! and falls back to a pure Rust implementation otherwise. It exposes a simple API for encryption and decryption
//! using the ChaCha20 stream cipher, suitable for cryptographic applications.
//!
//! # Examples
//!
//! Basic usage with a 32-byte key and 12-byte nonce:
//!
//! ```rust
//! use fast_chacha::FastChaCha20;
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let mut data = b"plaintext data to encrypt".to_vec();
//!
//! let mut cipher = FastChaCha20::new(&key, &nonce);
//! cipher.apply_keystream(&mut data);
//! // `data` now contains the encrypted bytes
//!
//! // To decrypt, reinitialize with the same key/nonce and apply again:
//! let mut cipher = FastChaCha20::new(&key, &nonce);
//! cipher.apply_keystream(&mut data);
//! // `data` is now the original plaintext
//! ```
//!
//! To use the pure Rust fallback implementation explicitly:
//!
//! ```rust
//! use fast_chacha::FastChaCha20;
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let mut data = b"some data".to_vec();
//! let mut cipher = FastChaCha20::new(&key, &nonce);
//! cipher.apply_keystream_pure(&mut data);
//! ```

#![no_std]
#![allow(unused_variables)]
#![allow(non_upper_case_globals)]
#![allow(unused_imports)]

use core::{
    ptr, slice,
    sync::atomic::{AtomicBool, Ordering},
};

pub mod fallback_chacha20;

/// Atomic flag indicating whether the fallback (pure Rust) implementation was triggered.
static FALLBACK_TRIGGERED: AtomicBool = AtomicBool::new(false);

/// Fallback ChaCha20 implementation using pure Rust.
///
/// # Arguments
/// * `out` - Output buffer for the keystream XOR result.
/// * `inp` - Input buffer to be encrypted/decrypted.
/// * `key` - 256-bit key as 8 u32 words.
/// * `counter` - 128-bit counter as 4 u32 words.
#[allow(unused_variables)]
fn fallback(out: &mut [u8], key: &[u32; 8], counter: &mut [u32; 4]) {
    out.chunks_mut(64).enumerate().for_each(|(i, out_chunk)| {
        // XOR the input chunk with the keystream generated from the key and counter
        fallback_chacha20::xor(out_chunk, key, counter);

        // Increment the counter for the next block
        counter[0] = counter[0].wrapping_add(1);
    });
}

/// C-compatible ChaCha20 function, used as a fallback or as the main implementation if assembly is not available.
///
/// # Safety
/// This function is unsafe because it operates on raw pointers.
///
/// # Arguments
/// * `out` - Pointer to output buffer.
/// * `inp` - Pointer to input buffer.
/// * `len` - Length of the input/output buffers.
/// * `key` - Pointer to the key (8 u32 words).
/// * `counter` - Pointer to the counter (4 u32 words).
#[no_mangle]
pub unsafe extern "C" fn ChaCha20_ctr32_c(
    out: *mut u8,
    inp: *const u8,
    len: usize,
    key: *const u32,
    counter: *const u32,
) {
    FALLBACK_TRIGGERED.store(true, Ordering::SeqCst);

    let out = slice::from_raw_parts_mut(out, len);
    let key = &*(key as *const [u32; 8]);
    let ctr = &mut *(counter as *mut [u32; 4]);

    fallback(out, key, ctr);
}

#[cfg(fast_chacha_asm)]
extern "C" {
    /// External assembly-optimized ChaCha20 function.
    fn ChaCha20_ctr32(
        out: *mut u8,
        inp: *const u8,
        len: usize,
        key: *const u32,
        counter: *const u32,
    );
}

#[cfg(not(fast_chacha_asm))]
/// Pure Rust fallback for ChaCha20_ctr32 if assembly is not enabled.
///
/// # Safety
/// This function is unsafe because it operates on raw pointers.
#[no_mangle]
pub unsafe extern "C" fn ChaCha20_ctr32(
    out: *mut u8,
    inp: *const u8,
    len: usize,
    key: *const u32,
    counter: *const u32,
) {
    ChaCha20_ctr32_c(out, inp, len, key, counter);
}

#[cfg(fast_chacha_asm)]
mod cpucaps;
#[cfg(fast_chacha_asm)]
pub use cpucaps::init as init_cpu_caps;
#[cfg(not(fast_chacha_asm))]
/// No-op CPU capabilities initialization when assembly optimizations are not enabled.
fn init_cpu_caps() {
    // No-op when assembly optimizations are not enabled
}

/// FastChaCha20: Main struct representing a ChaCha20 cipher instance.
///
/// Holds the key and counter state for encryption/decryption.
///
///
#[derive(Clone)]
pub struct FastChaCha20 {
    /// 256-bit key as 8 u32 words.
    key_words: [u32; 8],
    /// 128-bit counter as 4 u32 words.
    counter: [u32; 4],
}

impl FastChaCha20 {
    /// Creates a new FastChaCha20 instance with the given key and nonce.
    ///
    /// # Arguments
    /// * `key` - 32-byte (256-bit) key.
    /// * `nonce` - 12-byte (96-bit) nonce.
    ///
    /// # Panics
    /// Panics if the key or nonce are not the correct length.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let cipher = FastChaCha20::new(&key, &nonce);
    /// ```
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        assert!(key.len() == 32, "Key must be 32 bytes");
        assert!(nonce.len() == 12, "Nonce must be 12 bytes");

        let mut key_words = [0u32; 8];

        for i in 0..8 {
            key_words[i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        let mut counter = [0u32; 4];
        // The first counter word is left as zero; the next three are filled from the nonce.
        for i in 0..3 {
            counter[i + 1] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        Self { key_words, counter }
    }

    /// Applies the ChaCha20 keystream to the given data in-place, using the fastest available implementation.
    ///
    /// # Arguments
    /// * `data` - Mutable buffer to encrypt/decrypt.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let mut cipher = FastChaCha20::new(&key, &nonce);
    /// let mut data = [1u8, 2, 3, 4, 5];
    /// cipher.apply_keystream(&mut data);
    /// ```
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let len = data.len();

        init_cpu_caps();

        unsafe {
            ChaCha20_ctr32(
                data.as_mut_ptr(),
                data.as_mut_ptr(),
                len,
                self.key_words.as_ptr(),
                self.counter.as_mut_ptr(),
            )
        }
    }

    /// Applies the ChaCha20 keystream using the pure Rust fallback implementation.
    ///
    /// # Arguments
    /// * `data` - Mutable buffer to encrypt/decrypt.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let mut cipher = FastChaCha20::new(&key, &nonce);
    /// let mut data = [1u8, 2, 3, 4, 5];
    /// cipher.apply_keystream_pure(&mut data);
    /// ```
    pub fn apply_keystream_pure(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        fallback(data, &self.key_words, &mut self.counter);
    }

    /// Resets the internal counter to zero.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let mut cipher = FastChaCha20::new(&[0u8; 32], &[0u8; 12]);
    /// cipher.reset();
    /// ```
    pub fn reset(&mut self) {
        self.counter[0] = 0;
    }

    pub fn set_counter(&mut self, counter: u32) {
        self.counter[0] = counter;
    }

    /// Sets the internal counter to the position corresponding to the given byte offset.
    ///
    /// # Arguments
    /// * `pos` - Byte position to seek to.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let mut cipher = FastChaCha20::new(&[0u8; 32], &[0u8; 12]);
    /// cipher.seek(128);
    /// ```
    pub fn seek(&mut self, pos: u64) {
        self.counter[0] = (pos / 64) as u32;
    }

    /// Returns the current byte position in the stream.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let cipher = FastChaCha20::new(&[0u8; 32], &[0u8; 12]);
    /// let pos = cipher.current_pos();
    /// ```
    pub fn current_pos(&self) -> u64 {
        (self.counter[0] as u64) * 64
    }

    /// Creates a new FastChaCha20 instance with a custom initial counter value.
    ///
    /// # Arguments
    /// * `key` - 32-byte key.
    /// * `nonce` - 12-byte nonce.
    /// * `counter` - Initial counter value.
    ///
    /// # Example
    /// ```
    /// use fast_chacha::FastChaCha20;
    ///
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let cipher = FastChaCha20::new_with_counter(key, nonce, 42);
    /// ```
    pub fn new_with_counter(key: [u8; 32], nonce: [u8; 12], counter: u32) -> Self {
        let mut s = Self::new(&key, &nonce);
        s.counter[0] = counter;

        s
    }
}

/// Dummy static used for feature detection.
#[repr(align(16))]
struct Dummy([u8; 16]);
static mut DUMMY: Dummy = Dummy([0; 16]);

/// Checks if the assembly-optimized implementation is available at runtime.
///
/// Returns `true` if the assembly implementation is available, `false` otherwise.
///
/// # Example
/// ```
/// if fast_chacha::is_asm_available() {
///     // Use the fastest implementation
/// }
/// ```
pub fn is_asm_available() -> bool {
    FALLBACK_TRIGGERED.store(false, Ordering::SeqCst);
    unsafe {
        init_cpu_caps();
        let dummy_ptr = core::ptr::addr_of_mut!(DUMMY.0) as *mut u8;
        ChaCha20_ctr32(dummy_ptr, dummy_ptr, 0, dummy_ptr as *const u32, dummy_ptr as *const u32);
    }
    !FALLBACK_TRIGGERED.load(Ordering::SeqCst)
}
