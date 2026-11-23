//! Finds out whether the compiler has the AVX-512 intrinsics (stable from
//! Rust 1.89): the crate's minimum supported version is older, and builds
//! there without the AVX-512 kernels. And whether this is a build with
//! little or no optimisation (`opt-level` 0 or 1).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(wg_avx512)");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok());
    // "rustc 1.89.0 (…)": the second word, split at the dots.
    let new_enough = version
        .as_deref()
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| {
            let mut parts = v.split(['.', '-']);
            let major: u32 = parts.next()?.parse().ok()?;
            let minor: u32 = parts.next()?.parse().ok()?;
            Some((major, minor) >= (1, 89))
        })
        .unwrap_or(false);
    if new_enough {
        println!("cargo:rustc-cfg=wg_avx512");
    }

    // A build with little or no optimisation does not inline the vector
    // intrinsics into the kernels: what they compute with is then in
    // frames beneath the kernels' own, and the clean-up after a kernel
    // has to reach further down (`clear_frames`).
    println!("cargo:rustc-check-cfg=cfg(wg_low_opt)");
    println!("cargo:rerun-if-env-changed=OPT_LEVEL");
    if matches!(std::env::var("OPT_LEVEL").as_deref(), Ok("0" | "1")) {
        println!("cargo:rustc-cfg=wg_low_opt");
    }
}
