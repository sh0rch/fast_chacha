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
 * MIPS CPU feature detection module.
 *
 * This module provides functionality to detect available hardware capabilities
 * (such as DSP and MSA extensions) on MIPS CPUs at runtime. The detected
 * features are stored in a global atomic variable for use by other parts of
 * the library.
 */

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Auxiliary vector type for hardware capabilities.
pub const AT_HWCAP: usize = 16;

extern "C" {
    /// Retrieves the value of the given auxiliary vector type.
    ///
    /// # Arguments
    ///
    /// * `type_` - The type of auxiliary vector entry to retrieve.
    ///
    /// # Returns
    ///
    /// The value of the requested auxiliary vector entry.
    pub fn getauxval(type_: usize) -> usize;
}

/// Global atomic variable storing the detected MIPS CPU capabilities.
///
/// Bit 0: DSP extension available  
/// Bit 1: MSA extension available
#[no_mangle]
pub static OPENSSL_mipscap_P: AtomicU32 = AtomicU32::new(0);

/// Atomic flag indicating whether CPU feature detection has been performed.
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes the MIPS CPU feature detection.
///
/// This function queries the hardware capabilities using the auxiliary vector,
/// checks for the presence of DSP and MSA extensions, and stores the result
/// in the global `OPENSSL_mipscap_P` variable. The function is safe to call
/// multiple times, but detection will only be performed once.
///
/// # Safety
///
/// This function is unsafe because it accesses global mutable state and
/// calls an external C function.
#[inline(never)]
pub fn init() {
    // Ensure initialization is performed only once.
    if INITIALIZED.swap(true, Ordering::Relaxed) {
        return;
    }

    // Retrieve hardware capabilities from the auxiliary vector.
    let hw = unsafe { getauxval(AT_HWCAP) as u32 };

    let mut cap = 0;

    // Hardware capability flags for MIPS.
    const HWCAP_DSP: u32 = 1 << 7; // DSP extension
    const HWCAP_MSA: u32 = 1 << 18; // MSA extension

    // Check for DSP extension support.
    if hw & HWCAP_DSP != 0 {
        cap |= 1 << 0;
    }
    // Check for MSA extension support.
    if hw & HWCAP_MSA != 0 {
        cap |= 1 << 1;
    }

    // Store the detected capabilities.
    super::OPENSSL_mipscap_P.store(cap, Ordering::SeqCst);
    // Mark initialization as complete.
    INITIALIZED.store(true, Ordering::Release);
}
