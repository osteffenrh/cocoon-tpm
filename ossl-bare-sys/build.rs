// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const LINK_NAME_SYM_PREFIX: &str = "ossl_a52a4823_";

fn prefix_symbols() -> bool {
    env::var("CARGO_FEATURE_PREFIX_SYMBOLS").is_ok()
}

#[derive(Debug)]
struct BindgenCallbacks {
    prefix_symbols: bool,
}

impl bindgen::callbacks::ParseCallbacks for BindgenCallbacks {
    fn generated_link_name_override(
        &self,
        item_info: bindgen::callbacks::ItemInfo<'_>,
    ) -> Option<String> {
        if self.prefix_symbols {
            Some(String::from(LINK_NAME_SYM_PREFIX) + item_info.name)
        } else {
            None
        }
    }
}

fn main() {
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir.clone());
    let ossl_build_path = out_path.join("build");

    // Read integration metadata from the target-integration crate.
    // These env vars are set by the cocoon-tpm-ossl-bare-sys-target-integration
    // crate's build.rs via cargo::metadata. They are all optional — the default
    // (no-op) integration crate emits none of them, which gives a vanilla
    // host-native OpenSSL build.
    let integration_cppflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CPPFLAGS").ok();
    let integration_cflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CFLAGS").ok();
    let integration_bindgen_cflags = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_BINDGEN_CFLAGS").ok();
    let integration_configure_args = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_ARGS").ok();
    let integration_configure_config_file = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_CONFIG_FILE").ok();
    let integration_configure_target = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_TARGET").ok();
    let integration_link_search = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_LINK_SEARCH").ok();
    let integration_link_lib = env::var("DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_LINK_LIB").ok();

    // Sanity-check: if a custom target is specified, the config file must also
    // be present, and vice-versa. A half-configured build will silently produce
    // wrong results (e.g. auto-detecting the host platform instead of using the
    // intended target).
    if integration_configure_target.is_some() != integration_configure_config_file.is_some() {
        panic!(
            "Inconsistent integration metadata: CONFIGURE_TARGET={:?} but \
             CONFIGURE_CONFIG_FILE={:?}. Both must be set together.",
            integration_configure_target, integration_configure_config_file
        );
    }

    // Log received metadata so build failures are diagnosable.
    eprintln!("ossl-bare-sys: integration target={:?}, config_file={:?}, \
               args={:?}, cppflags={:?}, cflags={:?}",
              integration_configure_target, integration_configure_config_file,
              integration_configure_args, integration_cppflags, integration_cflags);

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

    // Sanity-check that EC was not accidentally disabled by Configure.
    // OpenSSL's Configure auto-adds "no-<alg>" for any algorithm whose
    // crypto/<alg>/ directory is missing from $srcdir (Configure lines ~329-334).
    // This catches submodule-init issues and wrong $srcdir resolution.
    let ec_dir = ossl_src_dir.join("crypto").join("ec");
    if !ec_dir.is_dir() {
        panic!(
            "OpenSSL source directory {ec_dir:?} does not exist. \
             The openssl git submodule may not be initialized. \
             Run: git submodule update --init --recursive"
        );
    }
    let config_h = ossl_build_path.join("include").join("openssl").join("configuration.h");
    let config_contents = std::fs::read_to_string(&config_h)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", config_h.display()));
    let ec_disabled = config_contents.lines().any(|line| {
        let trimmed = line.trim().trim_start_matches('#').trim();
        trimmed == "define OPENSSL_NO_EC"
    });
    if ec_disabled {
        let disabled: Vec<&str> = config_contents
            .lines()
            .filter(|l| l.contains("OPENSSL_NO_"))
            .collect();
        panic!(
            "OpenSSL Configure unexpectedly disabled EC.\n\
             Source dir: {}\n\
             Build dir: {}\n\
             crypto/ec exists: {}\n\
             All OPENSSL_NO_* in configuration.h:\n{}",
            ossl_src_dir.display(),
            ossl_build_path.display(),
            ec_dir.is_dir(),
            disabled.join("\n")
        );
    }

    // Build the shim library.
    // Generated headers (from .h.in templates: crypto.h, bio.h, …) live in
    // the build output; non-generated headers (bn.h, evp.h, …) live in the
    // source tree. Both must be on the include path so the compiler never
    // falls back to system OpenSSL headers of a different version.
    let ossl_include_dir = ossl_build_path.join("include");
    let ossl_src_include_dir = ossl_src_dir.join("include");
    let shim_src = src_dir.join("third-party").join("ossl_shims.c");
    let mut cc_build = cc::Build::new();
    cc_build
        .file(&shim_src)
        .include(src_dir.join("third-party"))
        .include(&ossl_include_dir)
        .include(&ossl_src_include_dir)
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

    if prefix_symbols() {
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
    }

    // Generate the binding.
    // Canonicalize paths so that bindgen's allowlist_file regexes match
    // even when libclang resolves symlinks or bind-mount targets.
    let canon = |p: PathBuf| -> String {
        p.canonicalize().unwrap_or(p).into_os_string().into_string().unwrap()
    };
    let ossl_src_rust_bindgen_hdr = canon(src_dir.join("third-party").join("wrapper.h"));
    let ossl_include_dir_str = canon(ossl_include_dir);
    // OpenSSL headers live in both the source tree and the build output.
    let ossl_src_include_dir_str = canon(src_dir.join("third-party").join("openssl").join("include"));
    let shim_include_dir = canon(src_dir.join("third-party"));
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
        .clang_arg(format!("-I{ossl_include_dir_str}"))
        .clang_arg(format!("-I{ossl_src_include_dir_str}"))
        .clang_arg(format!("-I{shim_include_dir}"));
    bindings = bindings.parse_callbacks(Box::new(BindgenCallbacks {
        prefix_symbols: prefix_symbols(),
    }));
    if let Some(bindgen_cflags) = integration_bindgen_cflags.as_ref() {
        // The integration crate supplies include paths for the target's C
        // library (e.g. a bare-metal libcrt).  Three adjustments ensure
        // bindgen uses only target headers and clang built-ins, regardless
        // of host distro or compiler defaults:
        //
        // 1. -nostdlibinc: suppress host system headers so bindgen never
        //    picks up host-side libc.  Required for cross-builds where the
        //    host and target may have different type widths.  Clang's own
        //    built-in headers (stddef.h, stdarg.h — compiler intrinsics,
        //    not libc) are kept.
        //
        // 2. -I → -idirafter: the target C library headers are searched
        //    AFTER clang's built-in headers.  Without this, a target-
        //    provided stddef.h shadows clang's own, corrupting the type
        //    system and causing bindgen to emit zero function bindings.
        //
        // 3. -fno-PIE: normalise __pie__ across host compilers.  Some
        //    target C libraries guard `#pragma GCC visibility push(hidden)`
        //    on __pie__.  On hosts where clang defaults to PIE (Ubuntu,
        //    Debian), __pie__ is defined, the pragma fires, and all
        //    subsequent function declarations get hidden visibility —
        //    bindgen's enable_function_attribute_detection() then silently
        //    drops them.  Hosts without PIE defaults (Fedora, RHEL) are
        //    unaffected, hiding the bug.  Since bindgen only parses headers
        //    and never generates code, PIE has no effect on the output
        //    beyond the __pie__ macro; -fno-PIE is kept unconditionally to
        //    avoid distro-dependent build failures.
        bindings = bindings
            .clang_arg("-nostdlibinc")
            .clang_arg("-fno-PIE");
        let flags = bindgen_cflags.split_ascii_whitespace().map(|f| {
            f.strip_prefix("-I")
                .map(|path| format!("-idirafter{path}"))
                .unwrap_or_else(|| f.to_string())
        });
        bindings = bindings.clang_args(flags);
    }
    bindings
        .generate()
        .expect("Failed to generate ossl bindings")
        .write_to_file(bindgen_wrapper_rs_out_path.clone())
        .expect("Failed to write ossl bindings");

    // Verify that critical bindings were generated.
    let wrapper_contents = std::fs::read_to_string(&bindgen_wrapper_rs_out_path)
        .expect("Failed to read generated bindings");
    assert!(
        wrapper_contents.contains("EC_POINT_new"),
        "Generated bindings are missing EC_POINT_new — bindgen \
         produced {} 'pub fn' entries. Check that the OpenSSL source \
         tree includes crypto/ec/ and that BINDGEN_CFLAGS does not \
         shadow clang's built-in headers.",
        wrapper_contents.matches("pub fn ").count()
    );

    // Included from lib.rs by means of this environment variable.
    println!(
        "cargo::rustc-env=OSSL_BARE_SYS_BINDGEN_WRAPPER_RS={}",
        bindgen_wrapper_rs_out_path.into_os_string().into_string().unwrap()
    );

    println!(
        "cargo::rustc-link-search={}",
        ossl_build_path.as_os_str().to_os_string().into_string().unwrap()
    );
    if prefix_symbols() {
        // Rename the archive to avoid conflicts with other crates that also link
        // libcrypto.a (e.g. libtcgtpm in SVSM). The symbols inside are already
        // prefixed, so only the archive name collides.
        let renamed_libcrypto = ossl_build_path.join("libossl_bare_crypto.a");
        std::fs::rename(&ossl_libcrypto, &renamed_libcrypto).unwrap();
        println!("cargo::rustc-link-lib=ossl_bare_crypto");
    } else {
        println!("cargo::rustc-link-lib=crypto");
    }

    // Export include paths so downstream crates can find the OpenSSL headers.
    println!(
        "cargo::metadata=OSSL_INCLUDE_DIR={}",
        ossl_build_path.join("include").to_str().unwrap()
    );
    println!(
        "cargo::metadata=OSSL_SRC_INCLUDE_DIR={}",
        src_dir
            .join("third-party")
            .join("openssl")
            .join("include")
            .to_str()
            .unwrap()
    );
    println!("cargo::metadata=OSSL_LIB_DIR={}", ossl_build_path.to_str().unwrap());

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
