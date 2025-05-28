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
 * x86 CPU capabilities detection module.
 *
 * This module provides functionality to detect and store CPU feature flags
 * for x86 and x86_64 architectures using the CPUID instruction. The detected
 * capabilities are stored in a global array compatible with OpenSSL's
 * expectations.
 */

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Global array holding CPU feature flags as detected by CPUID.
/// This array is compatible with OpenSSL's `OPENSSL_ia32cap_P`.
#[no_mangle]
pub static mut OPENSSL_ia32cap_P: [u32; 4] = [0; 4];

/// Atomic flag indicating whether CPU capabilities have been initialized.
pub static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes the CPU capabilities array using the CPUID instruction.
///
/// This function is safe to call multiple times, but will only perform
/// initialization once. It detects CPU features and stores them in the
/// `OPENSSL_ia32cap_P` array. The function uses architecture-specific
/// intrinsics to query the processor for supported features.
///
/// # Safety
///
/// This function is unsafe because it writes to a global mutable static
/// variable and uses architecture-specific intrinsics.
///
/// # Safety
/// This function is unsafe because it writes to a global mutable static
/// variable and uses architecture-specific intrinsics.
#[inline(never)]
pub fn init() {
    // Ensure initialization is performed only once.
    if INITIALIZED.swap(true, Ordering::Relaxed) {
        return;
    }

    // Import architecture-specific CPUID intrinsics.
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{__cpuid, __cpuid_count};

    // Query standard feature flags (EAX=1) and extended features (EAX=7, ECX=0).
    unsafe {
        let c1 = __cpuid(1);
        let c7 = __cpuid_count(7, 0);

        // Store feature flags in the global array.
        OPENSSL_ia32cap_P[0] = c1.edx;
        OPENSSL_ia32cap_P[1] = c1.ecx;
        OPENSSL_ia32cap_P[2] = c7.ebx;
        OPENSSL_ia32cap_P[3] = c7.ecx;
    }

    // Mark initialization as complete.
    INITIALIZED.store(true, Ordering::Release);
}
