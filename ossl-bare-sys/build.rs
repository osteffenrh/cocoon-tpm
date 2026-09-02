// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const LINK_NAME_SYM_PREFIX: &str = "ossl_a52a4823_";

#[derive(Debug)]
struct BindgenPrefixLinkNames {}

impl bindgen::callbacks::ParseCallbacks for BindgenPrefixLinkNames {
    fn generated_link_name_override(&self, item_info: bindgen::callbacks::ItemInfo<'_>) -> Option<String> {
        Some(String::from(LINK_NAME_SYM_PREFIX) + item_info.name)
    }
}

fn main() {
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());
    let ossl_build_path = out_path.join("build");

    // Read integration metadata from the target-integration crate.
    let integration_cppflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CPPFLAGS").ok();
    let integration_cflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CFLAGS").ok();
    let integration_bindgen_cflags =
        env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_BINDGEN_CFLAGS").ok();
    let integration_configure_args =
        env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_ARGS").ok();
    let integration_configure_config_file =
        env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_CONFIG_FILE").ok();
    let integration_configure_target =
        env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_TARGET").ok();
    let integration_link_search =
        env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_LINK_SEARCH").ok();
    let integration_link_lib =
        env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_LINK_LIB").ok();

    // Remove the libcrypto.a from a previous run, if any -- the symbol renaming
    // further below is not idempotent.
    let ossl_libcrypto = ossl_build_path.join("libcrypto.a");
    let _ = std::fs::remove_file(&ossl_libcrypto);

    // Build OpenSSL.
    let ossl_src_dir = src_dir.join("third-party").join("openssl");

    println!("cargo::rerun-if-changed={}", ossl_src_dir.to_str().unwrap());
    println!(
        "cargo::rerun-if-changed={}",
        src_dir.join("third-party").join("wrapper.h").to_str().unwrap()
    );
    println!(
        "cargo::rerun-if-changed={}",
        src_dir.join("third-party").join("ossl_shims.h").to_str().unwrap()
    );
    println!(
        "cargo::rerun-if-changed={}",
        src_dir.join("third-party").join("ossl_shims.c").to_str().unwrap()
    );

    let status = Command::new("mkdir")
        .current_dir(&out_path)
        .arg("-p")
        .arg(&ossl_build_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    let mut configure_cmd = Command::new(ossl_src_dir.join("Configure").to_str().unwrap());
    configure_cmd.current_dir(&ossl_build_path);
    // Custom target configuration file (e.g. openssl_svsm.conf).
    if let Some(config_file) = integration_configure_config_file.as_ref() {
        configure_cmd.arg(format!("--config={config_file}"));
    }
    configure_cmd.args([
            "--api=1.1.1",
            "disable-legacy",
            "no-afalgeng",
            "no-aria",
            "no-asm",
            "no-async",
            "no-atexit",
            "no-autoerrinit",
            "no-autoload-config",
            "no-capieng",
            "no-cast",
            // Keep deprecated APIs available — we need the legacy HMAC API.
            // "no-deprecated",
            "no-dgram",
            "no-docs",
            "no-dso",
            "no-dtls",
            "no-dtls1",
            "no-dtls1-method",
            "no-dtls1_2",
            "no-dtls1_2-method",
            "no-dynamic-engine",
            "no-engine",
            "no-filenames",
            "no-gost",
            "no-http",
            "no-idea",
            "no-ktls",
            "no-makedepend",
            "no-md4",
            "no-mdc2",
            "no-module",
            "no-multiblock",
            "no-nextprotoneg",
            "no-padlockeng",
            // "no-pic", -- need PIC for test binaries
            "no-poly1305",
            "no-posix-io",
            "no-psk",
            "no-quic",
            "no-rc2",
            "no-rc4",
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
    // Pass through integration flags.
    if let Some(cppflags) = integration_cppflags.as_ref() {
        configure_cmd.env("CPPFLAGS", cppflags);
    }
    if let Some(cflags) = integration_cflags.as_ref() {
        configure_cmd.env("CFLAGS", cflags);
    }
    if let Some(configure_args) = integration_configure_args.as_ref() {
        configure_cmd.args(configure_args.split_ascii_whitespace());
    }
    // Custom target name (e.g. "SVSM") — must come after all options.
    if let Some(target) = integration_configure_target.as_ref() {
        configure_cmd.arg(target);
    }
    let status = configure_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    let status = Command::new("make")
        .current_dir(&ossl_build_path)
        .arg("-j")
        .arg(num_cpus().to_string())
        .arg("build_libs")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // Build the shim library.
    let ossl_include_dir = ossl_build_path.join("include");
    let shim_src = src_dir.join("third-party").join("ossl_shims.c");
    let mut cc_build = cc::Build::new();
    cc_build
        .file(&shim_src)
        .include(src_dir.join("third-party"))
        .include(&ossl_include_dir)
        .warnings(true)
        .flag("-Wno-deprecated-declarations");
    if let Some(cppflags) = integration_cppflags.as_ref() {
        for flag in cppflags.split_ascii_whitespace() {
            cc_build.flag(flag);
        }
    }
    if let Some(cflags) = integration_cflags.as_ref() {
        for flag in cflags.split_ascii_whitespace() {
            cc_build.flag(flag);
        }
    }
    cc_build.compile("ossl_shims");

    // Prefix all symbols in libcrypto.a to avoid name collisions.
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
        "strpbrk",
        "strrchr",
        "strspn",
        "strstr",
        "strtol",
        "strtoul",
        "tolower",
        "syscall",
        "sysconf",
        "time",
        "vsnprintf",
        "__isoc23_strtol",
        "__isoc23_strtoul",
        "atoi",
        "clearerr",
        "clock_gettime",
        "close",
        "closedir",
        "closelog",
        "__ctype_b_loc",
        "__ctype_tolower_loc",
        "fstat",
        "getegid",
        "geteuid",
        "getgid",
        "getpid",
        "getuid",
        "gmtime",
        "gettimeofday",
        "isspace",
        "mlock",
        "mprotect",
        "nanosleep",
        "opendir",
        "openlog",
        "posix_memalign",
        "readdir",
        "secure_getenv",
        "select",
        "setbuf",
        "shmat",
        "shmdt",
        "shmget",
        "stat",
        "strcpy",
        "strcspn",
        "strdup",
        "strncpy",
        "syslog",
        "uname",
        "__xpg_strerror_r",
        "gmtime_r",
        "pthread_attr_destroy",
        "pthread_attr_init",
        "pthread_attr_setdetachstate",
        "pthread_cond_broadcast",
        "pthread_cond_destroy",
        "pthread_cond_init",
        "pthread_cond_signal",
        "pthread_cond_timedwait",
        "pthread_cond_wait",
        "pthread_create",
        "pthread_exit",
        "pthread_join",
        "pthread_key_delete",
        "pthread_mutex_destroy",
        "pthread_mutex_init",
        "pthread_mutex_trylock",
        "pthread_self",
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

    // Also prefix symbols in the shim library so they match the bindgen
    // link_name overrides. The shim .a is placed by cc in OUT_DIR.
    let shim_lib = out_path.join("libossl_shims.a");
    let status = Command::new("objcopy")
        .arg(format!("--prefix-symbols={LINK_NAME_SYM_PREFIX}"))
        .arg(&shim_lib)
        .arg(&shim_lib)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // The shim references OpenSSL functions that are now prefixed in
    // libcrypto.a. Rename those back to the prefixed versions in the shim lib.
    // Actually, the shim lib's undefined refs to OpenSSL symbols need to get
    // the prefix added - which --prefix-symbols already did above. The only
    // symbols we need to un-prefix are the libc ones.
    let mut cmd = Command::new("objcopy");
    for sym in ["_GLOBAL_OFFSET_TABLE_", "memset", "memcpy", "memmove"] {
        cmd.arg("--redefine-sym")
            .arg(format!("{LINK_NAME_SYM_PREFIX}{sym}={sym}"));
    }
    let status = cmd
        .arg(&shim_lib)
        .arg(&shim_lib)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    // Generate the binding.
    let ossl_src_rust_bindgen_hdr = src_dir
        .join("third-party")
        .join("wrapper.h")
        .into_os_string()
        .into_string()
        .unwrap();
    let ossl_include_dir_str = ossl_include_dir.into_os_string().into_string().unwrap();
    // OpenSSL headers live in both the source tree and the build output.
    let ossl_src_include_dir = src_dir.join("third-party").join("openssl").join("include");
    let ossl_src_include_dir_str = ossl_src_include_dir.into_os_string().into_string().unwrap();
    let shim_include_dir = src_dir.join("third-party").into_os_string().into_string().unwrap();
    let bindgen_wrapper_rs_out_path = out_path.join("wrapper.rs");
    let mut bindings = bindgen::Builder::default()
        .header(&ossl_src_rust_bindgen_hdr)
        .allowlist_file(&ossl_src_rust_bindgen_hdr)
        .allowlist_file(format!("{}.*\\.h", ossl_include_dir_str.clone() + "/openssl/"))
        .allowlist_file(format!("{}.*\\.h", ossl_src_include_dir_str.clone() + "/openssl/"))
        .allowlist_file(format!("{}.*ossl_shims\\.h", shim_include_dir.clone() + "/"))
        .enable_function_attribute_detection()
        .use_core()
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .rustified_enum("point_conversion_form_t")
        .parse_callbacks(Box::new(BindgenPrefixLinkNames {}))
        .clang_arg(format!("-I{ossl_include_dir_str}"))
        .clang_arg(format!("-I{ossl_src_include_dir_str}"))
        .clang_arg(format!("-I{shim_include_dir}"));
    if let Some(bindgen_cflags) = integration_bindgen_cflags.as_ref() {
        bindings = bindings.clang_args(bindgen_cflags.split_ascii_whitespace());
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

    // Rename the archive to avoid conflicts with other crates that also link
    // libcrypto.a (e.g. libtcgtpm in SVSM). The symbols inside are already
    // prefixed, so only the archive name collides.
    let renamed_libcrypto = ossl_build_path.join("libossl_bare_crypto.a");
    std::fs::rename(&ossl_libcrypto, &renamed_libcrypto).unwrap();

    println!(
        "cargo::rustc-link-search={}",
        ossl_build_path.as_os_str().to_os_string().into_string().unwrap()
    );
    println!("cargo::rustc-link-lib=ossl_bare_crypto");

    // Forward any additional link paths/libs from the integration crate.
    if let Some(link_search) = integration_link_search.as_ref() {
        println!("cargo::rustc-link-search={link_search}");
    }
    if let Some(link_lib) = integration_link_lib.as_ref() {
        println!("cargo::rustc-link-lib={link_lib}");
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}
