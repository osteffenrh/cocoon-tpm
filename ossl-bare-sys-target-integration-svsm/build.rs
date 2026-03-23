// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    // See bssl-bare-sys' build.rs for a list and meaning of metadata variables recognized.
    // println!("cargo::metadata=CPPFLAGS=");
    // println!("cargo::metadata=BINDGEN_CFLAGS=");
    // println!("cargo::metadata=CFLAGS=");
    // println!("cargo::metadata=CXXFLAGS=");
    // println!("cargo::metadata=LINK_SEARCH={}", ...);
    // println!("cargo::metadata=LINK_LIB={}", ...);

    // Set the CMAKE_SYSTEM_NAME for embedded/standalone builds
    // println!("cargo::metadata=CMAKE_SYSTEM_NAME=Generic");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());

    // Remove the libcrypto.a from a previous run, if any -- the symbol renaming
    // further below is not idempotent.
    let libcrt = out_path.join("build").join("libcrt.a");
    let _ = std::fs::remove_file(libcrt);

    let libcrt_src_dir = "third-party/libcrt";
    println!("cargo::rerun-if-changed={libcrt_src_dir}");
    let status = Command::new("make").arg("-C").arg(libcrt_src_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    // TODO finish
}
