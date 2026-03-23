// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, os};

const LINK_NAME_SYM_PREFIX: &str = "ossl_a52a4823_";

#[derive(Debug)]
struct BindgenPrefixLinkNames {}

impl bindgen::callbacks::ParseCallbacks for BindgenPrefixLinkNames {
    fn generated_link_name_override(&self, item_info: bindgen::callbacks::ItemInfo<'_>) -> Option<String> {
        Some(String::from(LINK_NAME_SYM_PREFIX) + item_info.name)
    }
}

fn main() {
    let src_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());
    let ossl_build_path = out_path.clone().join("build");

    // Remove the libcrypto.a from a previous run, if any -- the symbol renaming
    // further below is not idempotent.
    let ossl_libcrypto = ossl_build_path.join("libcrypto.a");
    let _ = std::fs::remove_file(&ossl_libcrypto);

    // let integration_cppflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CPPFLAGS").ok();
    // let integration_cflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CFLAGS").ok();
    // let integration_cxxflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CXXFLAGS").ok();
    // let integration_asflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_ASFLAGS").ok();
    let integration_bindgen_cflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_BINDGEN_CFLAGS").ok();
    //
    // Build openssl.
    let ossl_src_dir = src_dir.clone().join("third-party").join("openssl");

    println!("cargo::rerun-if-changed={}", ossl_src_dir.to_str().unwrap());

    let status = Command::new("mkdir")
        .current_dir(&out_path)
        .arg("-p")
        .arg(&ossl_build_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    let mut cmd = Command::new(ossl_src_dir.join("Configure").to_str().unwrap());
    let cmd = cmd.current_dir(&ossl_build_path).args([
        "--api=1.1.1",
        "disable-legacy",
        "no-afalgeng",
        "no-aria",
        "no-asm",
        "no-async",
        "no-atexit",
        "no-autoerrinit",
        "no-autoload-config",
        "no-bf",
        "no-blake2",
        "no-capieng",
        "no-cast",
        "no-chacha",
        "no-cmac",
        "no-cmp",
        "no-cms",
        "no-ct",
        "no-deprecated",
        "no-des",
        "no-dgram",
        "no-dh",
        "no-docs",
        "no-dsa",
        "no-dso",
        "no-dtls",
        "no-dtls1",
        "no-dtls1-method",
        "no-dtls1_2",
        "no-dtls1_2-method",
        "no-dynamic-engine",
        "no-ec2m",
        "no-ecdh",
        "no-ecdsa",
        "no-ecx",
        "no-egd",
        "no-engine",
        "no-err",
        "no-filenames",
        "no-gost",
        "no-http",
        "no-idea",
        "no-ktls",
        "no-makedepend",
        "no-md4",
        "no-mdc2",
        "no-ml-dsa",
        "no-ml-kem",
        "no-module",
        "no-multiblock",
        "no-nextprotoneg",
        "no-ocb",
        "no-ocsp",
        "no-padlockeng",
        "no-pic",
        "no-poly1305",
        "no-posix-io",
        "no-psk",
        "no-quic",
        "no-rc2",
        "no-rc4",
        "no-rfc3779",
        "no-rmd160",
        "no-scrypt",
        "no-seed",
        "no-shared",
        "no-siphash",
        "no-siv",
        "no-sm2",
        "no-sm2-precomp",
        "no-sm3",
        "no-sm4",
        "no-sock",
        "no-srp",
        "no-srtp",
        "no-sse2",
        "no-ssl",
        "no-ssl-trace",
        "no-ssl3-method",
        "no-static-engine",
        "no-stdio",
        "no-tests",
        "no-thread-pool",
        "no-threads",
        "no-tls1",
        "no-tls1-method",
        "no-tls1_1",
        "no-tls1_1-method",
        "no-tls1_2",
        "no-tls1_2-method",
        "no-tls1_3",
        "no-ts",
        "no-ui-console",
        "no-uplink",
        "no-whirlpool",
    ]);

    let status = cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit()).status().unwrap();
    assert!(status.success());

    let make = Command::new("make")
        .current_dir(&ossl_build_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(make.success());

    let status = Command::new("objcopy")
        .arg(format!("--prefix-symbols={LINK_NAME_SYM_PREFIX}"))
        .arg(&ossl_libcrypto)
        .arg(&ossl_libcrypto)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // And rename the undefined references back.
    let mut cmd = Command::new("objcopy");
    for sym in [
        "_GLOBAL_OFFSET_TABLE_",
        "__assert_fail",
        "__errno_location",
        "__isoc23_sscanf",
        "abort",
        "bsearch",
        "calloc",
        "errno",
        "fclose",
        "feof",
        "ferror",
        "fflush",
        "fgets",
        "fopen",
        "fopen64",
        "fprintf",
        "fputc",
        "fputs",
        "fread",
        "free",
        "fseek",
        "ftell",
        "fwrite",
        "getauxval",
        "getentropy",
        "getenv",
        "madvise",
        "malloc",
        "memchr",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "mmap",
        "munmap",
        "open",
        "perror",
        "pthread_getspecific",
        "pthread_key_create",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_once",
        "pthread_rwlock_destroy",
        "pthread_rwlock_init",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_unlock",
        "pthread_rwlock_wrlock",
        "pthread_setspecific",
        "read",
        "qsort",
        "realloc",
        "snprintf",
        "sscanf",
        "stderr",
        "strchr",
        "strcmp",
        "strerror",
        "strlen",
        "strncmp",
        "syscall",
        "sysconf",
        "time",
        "vsnprintf",
        // C++ runtime symbols (libstdc++).
        "_ZSt21__glibcxx_assert_failPKciS0_S0_",
    ] {
        cmd.arg("--redefine-sym")
            .arg(format!("{LINK_NAME_SYM_PREFIX}{sym}={sym}"));
    }
    let status = cmd
        .arg(&ossl_libcrypto)
        .arg(&ossl_libcrypto)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // Generate the binding.
    // Essentially translated verbatim from boringssl/rust/bssl-sys/CMakeLists.txt.
    let ossl_src_path = PathBuf::from(ossl_src_dir);
    let ossl_src_rust_bssl_sys_bindgen_hdr = PathBuf::from("third-party")
        .join("wrapper.h")
        .into_os_string()
        .into_string()
        .unwrap();
    let ossl_src_include_path = ossl_src_path.join("include");
    let ossl_src_include_dir = ossl_src_include_path.clone().into_os_string().into_string().unwrap();
    let bindgen_wrapper_rs_out_path = out_path.join("wrapper.rs");
    // wrap_static_fns(true) is not possible unfortunately, as it would ignore
    // functions with a link_name_override(), which includes all for some
    // reason.
    let mut bindings = bindgen::Builder::default()
        .header(&ossl_src_rust_bssl_sys_bindgen_hdr)
        .allowlist_file(ossl_src_rust_bssl_sys_bindgen_hdr)
        .allowlist_file(format!(
            "{}.*\\.h",
            ossl_src_include_path
                .join("openssl")
                .into_os_string()
                .into_string()
                .unwrap()
        ))
        .enable_function_attribute_detection()
        .use_core()
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .rustified_enum("point_conversion_form_t")
        .parse_callbacks(Box::new(BindgenPrefixLinkNames {}))
        .clang_arg(format!("-I{ossl_src_include_dir}"));
    if let Some(integration_bindgen_cflags) = integration_bindgen_cflags.as_ref() {
        bindings = bindings.clang_args(integration_bindgen_cflags.split_ascii_whitespace());
    }
    bindings
        .generate()
        .expect("Failed to generate ossl bindings")
        .write_to_file(bindgen_wrapper_rs_out_path.clone())
        .expect("Failed to write ossl bindings");
    // Included from lib.rs by means of this environment variable.
    println!(
        "cargo::rustc-env=OSSL_BARE_SYS_BINDGEN_WRAPPER_RS={}",
        bindgen_wrapper_rs_out_path.into_os_string().into_string().unwrap()
    );

    println!(
        "cargo::rustc-link-search={}",
        ossl_build_path.as_os_str().to_os_string().into_string().unwrap()
    );
    // Add the generated objects to the link.
    println!("cargo::rustc-link-lib=crypto");
}
