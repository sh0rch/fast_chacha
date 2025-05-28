// build.rs

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(chacha20_force_soft)");
    println!("cargo:rustc-check-cfg=cfg(chacha20_force_neon)");
    println!("cargo:rustc-check-cfg=cfg(fast_chacha_asm)");

    // Identify target triple and features
    //let target = env::var("TARGET").unwrap(); // e.g. "aarch64-apple-darwin"
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap(); // e.g. "aarch64"
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap(); // e.g. "macos"
    let features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();

    // Prepare OUT_DIR for generated headers and patched .S
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Set up cc::Build
    let mut build = cc::Build::new();
    // run .S through CPP so we can define/replace directives
    build.flag_if_supported("-xassembler-with-cpp");
    // include OUT_DIR first, so our stub headers are found
    build.include(&out_dir);
    build.include("asm");
    build.warnings(false);

    // 3) Pick the right .S file (or fallback)
    let src_s = match (arch.as_str(), os.as_str()) {
        // x86 / x86_64
        ("x86_64", "linux") => "asm/chacha-x86_64-linux.S",
        ("x86_64", "macos") => "asm/chacha-x86_64-macosx.S",
        ("x86_64", "windows") => "asm/chacha-x86_64-masm.asm",
        ("x86", "linux") => "asm/chacha-x86-linux.S",
        //("x86", "windows") => "asm/chacha-x86-nasm.S",

        // ARMv8-A (+SVE) and ARMv4/v7
        ("aarch64", "linux") => "asm/chacha-armv8-linux.S",
        ("aarch64", "macos") => "asm/chacha-armv8-macosx.S",
        ("aarch64", "windows") => "asm/chacha-armv8-masm.asm",
        ("arm", "linux") => "asm/chacha-armv4-linux.S",
        ("arm", "macos") => "asm/chacha-armv4-macosx.S",

        // MIPS 32/64
        ("mips", "linux") | ("mipsel", "linux") => "asm/chacha-mips-o32.S",
        ("mips64", "linux") | ("mips64el", "linux") => "asm/chacha-mips-n64.S",
        /*
        // PowerPC 64
        ("powerpc64", "linux") => "asm/chacha-ppc64-elf.S",

        // RISC-V 64
        ("riscv64", "linux") => "asm/chacha-riscv64-lp64d.S",
        */
        // fallback to pure-Rust
        _ => {
            println!("cargo:warning=fast_chacha: no ASM for {}-{}, using Rust fallback", arch, os);
            return;
        }
    };

    // 4) For macOS, post-process the .S: replace `.hidden`, ADRP/LO12 → @PAGE/@PAGEOFF
    //    and write patched file into OUT_DIR
    let final_s = {
        let src_path = Path::new(src_s);
        let file_stem = src_path.file_stem().unwrap().to_string_lossy();
        let dst = out_dir.join(format!("{}.patched.S", file_stem));

        match os.as_str() {
            "macos" => {
                if std::env::var_os("MACOSX_DEPLOYMENT_TARGET").is_none() {
                    std::env::set_var("MACOSX_DEPLOYMENT_TARGET", "11.0");
                }
                // run cpp with hidden→private_extern
                let cpp_out = Command::new("cpp")
                    .args(["-P", "-xassembler-with-cpp", "-Dhidden=private_extern", src_s])
                    .output()
                    .expect("failed to run cpp for .S postprocess");

                let mut asm = String::from_utf8(cpp_out.stdout).expect("non-UTF8 after cpp");

                // apply ADRP/LO12 → @PAGE/@PAGEOFF for OpenSSL_armcap_P and Lsigma
                asm = asm
                    .replace(",OPENSSL_armcap_P", ",_OPENSSL_armcap_P@PAGE")
                    .replace(":lo12:OPENSSL_armcap_P", "_OPENSSL_armcap_P@PAGEOFF")
                    .replace(",Lsigma", ",Lsigma@PAGE")
                    .replace(":lo12:Lsigma", "Lsigma@PAGEOFF");

                if arch == "aarch64" {
                    // replace .L with _L for aarch64
                    asm = asm
                        .replace(
                            ".hidden\tOPENSSL_armcap_P",
                            ".hidden _OPENSSL_armcap_P\n\
                        .globl  _OPENSSL_armcap_P\n\
                        .globl  OPENSSL_armcap_P\n\
                        OPENSSL_armcap_P = _OPENSSL_armcap_P",
                        )
                        .replace(
                            ".globl\tChaCha20_ctr32",
                            ".globl  _ChaCha20_ctr32\n\
                     .globl  ChaCha20_ctr32\n\
                     .set    _ChaCha20_ctr32,ChaCha20_ctr32",
                        );
                    asm.push_str(
                        "\n\
                     // ---------- export NEON kernel (alias) -----------------------\n\
                     .globl  ChaCha20_neon\n\
                     .globl  _ChaCha20_neon\n\
                     .set    _ChaCha20_neon, ChaCha20_neon\n",
                    );

                    asm.push_str(
                        "\n\
                             // ---- macOS stub: SVE label aliases NEON implementation --------\n\
                             .globl  _ChaCha20_ctr32_sve\n\
                             .globl  ChaCha20_ctr32_sve\n\
                             .set    _ChaCha20_ctr32_sve, _ChaCha20_neon\n\
                             .set    ChaCha20_ctr32_sve,  _ChaCha20_neon\n",
                    );
                }
                fs::write(&dst, asm).expect("failed to write patched .S");
                dst
            }
            "linux" => {
                let mut asm = std::fs::read_to_string(src_path).unwrap();
                if arch == "aarch64" {
                    // нормализуем глобальные имена
                    asm = asm
                        .replace(
                            ".globl\tChaCha20_ctr32",
                            ".globl _ChaCha20_ctr32\n.globl ChaCha20_ctr32\n\
                  .set   _ChaCha20_ctr32,ChaCha20_ctr32",
                        )
                        .replace(
                            ".globl\tChaCha20_neon",
                            ".globl _ChaCha20_neon\n.globl ChaCha20_neon\n\
                  .set   _ChaCha20_neon,ChaCha20_neon",
                        );

                    if !features.contains("sve") {
                        asm.push_str(
                            "\n\
                        .globl  ChaCha20_ctr32_sve\n\
                        .globl  _ChaCha20_ctr32_sve\n\
                        .set    _ChaCha20_ctr32_sve, ChaCha20_ctr32\n\
                        .set    ChaCha20_ctr32_sve,  ChaCha20_ctr32\n",
                        );
                    }
                }
                fs::write(&dst, asm).expect("failed to write patched .S");
                dst
            }
            _ => PathBuf::from(src_s),
        }
    };

    // 5) Compile the chosen file
    build
        .file(final_s)
        .flag_if_supported("-fPIC")
        .flag_if_supported("--target-cpu=native")
        .compile("fast_chacha_asm");

    println!("cargo:rustc-cfg=fast_chacha_asm");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);

    println!("cargo:rustc-link-lib=static=fast_chacha_asm");
    println!("cargo:rerun-if-changed=build.rs");
}
