// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

//! Compare the FFI mirror with sizeof/alignment/offsetof from the C headers.
//! The small C probe uses CMake and the target's native C compiler.

use opentlv_sys::{tlv_fixed_format_t, tlv_fixed_identifier_t, tlv_fixed_length_t};
use std::mem::{align_of, size_of, MaybeUninit};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

// std::mem::offset_of! requires Rust 1.77; the binding supports Rust 1.70.
macro_rules! member_offset {
    ($type:ty, $member:ident) => {{
        let storage = MaybeUninit::<$type>::uninit();
        let base = storage.as_ptr();
        // SAFETY: addr_of! forms a field pointer without reading uninitialized data.
        unsafe { std::ptr::addr_of!((*base).$member) as usize - base as usize }
    }};
}

fn run(command: &mut Command) -> Output {
    let output = command
        .output()
        .expect("ABI probe requires CMake and a C compiler");
    assert!(
        output.status.success(),
        "{command:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn fixed_field_and_format_layouts_match_c() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let build =
        std::env::temp_dir().join(format!("opentlv-fixed-abi-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&build).expect("cannot create C ABI probe build directory");
    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(manifest.join("tests/abi_probe"))
        .arg("-B")
        .arg(&build)
        .arg(format!(
            "-DOPENTLV_SOURCE_DIR={}",
            manifest.join("../../..").display()
        ));
    if cfg!(all(target_os = "windows", target_env = "msvc")) {
        configure.arg("-A").arg(if cfg!(target_arch = "x86") {
            "Win32"
        } else if cfg!(target_arch = "aarch64") {
            "ARM64"
        } else {
            "x64"
        });
    } else if cfg!(target_arch = "x86") {
        configure.arg("-DCMAKE_C_FLAGS=-m32");
    }
    run(&mut configure);
    run(Command::new("cmake")
        .arg("--build")
        .arg(&build)
        .args(["--config", "Release"]));
    let name = if cfg!(windows) {
        "abi_probe.exe"
    } else {
        "abi_probe"
    };
    let executable = [build.join("Release").join(name), build.join(name)]
        .into_iter()
        .find(|path| path.is_file())
        .expect("missing C ABI probe executable");
    let output = run(&mut Command::new(executable));
    let native: Vec<usize> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    let rust = [
        size_of::<tlv_fixed_identifier_t>(),
        align_of::<tlv_fixed_identifier_t>(),
        member_offset!(tlv_fixed_identifier_t, size),
        size_of::<tlv_fixed_length_t>(),
        align_of::<tlv_fixed_length_t>(),
        member_offset!(tlv_fixed_length_t, size),
        member_offset!(tlv_fixed_length_t, byte_order),
        size_of::<tlv_fixed_format_t>(),
        align_of::<tlv_fixed_format_t>(),
        member_offset!(tlv_fixed_format_t, identifier),
        member_offset!(tlv_fixed_format_t, length),
        member_offset!(tlv_fixed_format_t, element_order),
        member_offset!(tlv_fixed_format_t, length_scope),
    ];
    assert_eq!(
        native, rust,
        "Rust Fixed FFI layout differs from the C headers"
    );
    std::fs::remove_dir_all(&build).expect("cannot clean up C ABI probe build directory");
}
