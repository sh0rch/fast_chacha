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
 * ARM CPU capabilities detection module.
 *
 * This module provides runtime detection of ARM CPU features relevant for cryptographic
 * operations, such as AES and PMULL instructions. It sets the global variable
 * `OPENSSL_armcap_P` with the detected capabilities, which can be used by other
 * parts of the library to enable optimized code paths.
 */

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Global variable holding ARM CPU capabilities flags.
/// This variable is set during initialization and used by cryptographic routines.
#[no_mangle]
pub static mut OPENSSL_armcap_P: u32 = 0;

/// Atomic flag indicating whether CPU capabilities have been initialized.
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes ARM CPU capabilities detection.
///
/// This function checks if initialization has already occurred using an atomic flag.
/// Depending on the target architecture, it calls the appropriate submodule's `init` function
/// to detect CPU features and set `OPENSSL_armcap_P`.
/// If the architecture is not supported, it sets the capabilities to zero.
///
/// # Safety
/// This function is safe to call multiple times; initialization will only occur once.
#[inline(never)]
pub fn init() {
    // Ensure initialization happens only once.
    if INITIALIZED.swap(true, Ordering::Relaxed) {
        return;
    }

    // For Apple Silicon (AArch64 on Apple), set the capabilities directly.
    #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
    unsafe {
        super::OPENSSL_armcap_P = (1 << 0) | (1 << 3) | (1 << 4);
    }

    // For AArch64 (64-bit ARM), call the aarch64-specific initialization.
    #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
    aarch64::init();

    // For 32-bit ARM on Linux, call the arm-specific initialization.
    #[cfg(all(target_arch = "arm", target_os = "linux"))]
    arm::init();

    // For unsupported architectures, set capabilities to zero.
    #[cfg(not(any(
        all(target_arch = "aarch64", target_vendor = "apple"),
        all(target_arch = "aarch64", not(target_vendor = "apple")),
        all(target_arch = "arm", target_os = "linux")
    )))]
    unsafe {
        OPENSSL_armcap_P = 0;
    }
    // Mark initialization as complete with Release ordering.
    INITIALIZED.store(true, Ordering::Release);
}

/// AArch64 (64-bit ARM) specific CPU feature detection.
#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
mod aarch64 {
    use super::OPENSSL_armcap_P;

    /// Reads the ID_AA64ISAR0_EL1 system register to determine instruction set features.
    ///
    /// # Safety
    /// Uses inline assembly to access privileged system registers.
    #[inline(always)]
    unsafe fn read_isar0() -> u64 {
        let v: u64;
        // Read the system register ID_AA64ISAR0_EL1 into variable v.
        core::arch::asm!(
            "mrs {v}, ID_AA64ISAR0_EL1",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags)
        );
        v
    }

    /// Detects AArch64 CPU features and sets the global capabilities variable.
    ///
    /// Sets bits in `OPENSSL_armcap_P` if AES and PMULL instructions are available.
    pub(super) fn init() {
        // Read the instruction set attribute register.
        let isar0 = unsafe { read_isar0() };
        let mut cap: u32 = 1; // Base capability flag
                              // Check for AES support (field at bits [7:4], value >= 2)
        if ((isar0 >> 4) & 0xF) >= 2 {
            cap |= 1 << 3;
        }
        // Check for PMULL support (field at bits [11:8], value >= 1)
        if ((isar0 >> 8) & 0xF) >= 1 {
            cap |= 1 << 4;
        }
        // Set the global capability variable.
        unsafe {
            OPENSSL_armcap_P = cap;
        }
    }
}

/// ARM (32-bit) Linux-specific CPU feature detection.
#[cfg(all(target_arch = "arm", target_os = "linux"))]
mod arm {
    use super::OPENSSL_armcap_P;

    /// Auxiliary vector type for hardware capabilities.
    const AT_HWCAP: usize = 16;
    /// Hardware capability bit for AES instructions.
    const HWCAP_AES: usize = 1 << 0;
    /// Hardware capability bit for PMULL instructions.
    const HWCAP_PMULL: usize = 1 << 1;

    /// FFI binding to the `getauxval` libc function, used to read hardware capabilities.
    extern "C" {
        fn getauxval(type_: usize) -> usize;
    }

    /// Detects ARM CPU features and sets the global capabilities variable.
    ///
    /// Uses the auxiliary vector to check for AES and PMULL support.
    pub(super) fn init() {
        let mut cap: u32 = 1; // Base capability flag
                              // Read hardware capabilities from the auxiliary vector.
        let hw = unsafe { getauxval(AT_HWCAP) };
        // Check for AES support
        if hw & HWCAP_AES != 0 {
            cap |= 1 << 3;
        }
        // Check for PMULL support
        if hw & HWCAP_PMULL != 0 {
            cap |= 1 << 4;
        }
        // Set the global capability variable.
        unsafe {
            OPENSSL_armcap_P = cap;
        }
    }
}
