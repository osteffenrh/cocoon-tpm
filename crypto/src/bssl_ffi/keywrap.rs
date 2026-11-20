// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! BoringSSL FFI backend for AES key wrapping (RFC 3394 and RFC 5649).
//!
//! BoringSSL does not provide the wrap ciphers through its EVP interface,
//! use the low-level `AES_wrap_key()` / `AES_unwrap_key()` and their padded
//! counterparts from `<openssl/aes.h>` instead.

// Lifetimes are not obvious at first sight here, make them explicit.
#![allow(clippy::needless_lifetimes)]

use cocoon_tpm_bssl_bare_sys as bssl_bare_sys;

use super::symcipher::{BsslAesDecKey, BsslAesEncKey};
use crate::CryptoError;
use crate::symcipher::SymBlockCipherAesKeySize;
use core::ptr;

// The input length checks have already been conducted by the public
// keywrap module, the backend may rely on them.
pub fn aes_kw_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    let aes_key = BsslAesEncKey::new(kek, kek_to_key_size(kek.len())?)?;

    // SAFETY: aes_key holds a valid AES key configured for encryption as
    // required by AES_wrap_key(). The default (RFC 3394) initial value gets
    // used by passing NULL. out is of at least in_len + 8 bytes, as
    // validated by the public keywrap module.
    let ret = unsafe {
        bssl_bare_sys::AES_wrap_key(
            aes_key.as_ptr(),
            ptr::null(),
            wrapped.as_mut_ptr(),
            key.as_ptr(),
            key.len(),
        )
    };
    if ret < 0 {
        return Err(CryptoError::Internal);
    }
    Ok(ret as usize)
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    let aes_key = BsslAesDecKey::new(kek, kek_to_key_size(kek.len())?)?;

    // SAFETY: aes_key holds a valid AES key configured for decryption as
    // required by AES_unwrap_key(). The default (RFC 3394) initial value gets
    // used by passing NULL. out is of at least in_len - 8 bytes, as validated
    // by the public keywrap module.
    let ret = unsafe {
        bssl_bare_sys::AES_unwrap_key(
            aes_key.as_ptr(),
            ptr::null(),
            key.as_mut_ptr(),
            wrapped.as_ptr(),
            wrapped.len(),
        )
    };
    if ret < 0 {
        // A negative return value indicates a failed integrity check.
        return Err(CryptoError::SignatureVerificationFailure);
    }
    Ok(ret as usize)
}

pub fn aes_kwp_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    let aes_key = BsslAesEncKey::new(kek, kek_to_key_size(kek.len())?)?;

    let mut out_len: usize = 0;
    // SAFETY: aes_key holds a valid AES key configured for encryption as
    // required by AES_wrap_key_padded(). max_out is the length of wrapped as
    // validated by the public keywrap module.
    let ret = unsafe {
        bssl_bare_sys::AES_wrap_key_padded(
            aes_key.as_ptr(),
            wrapped.as_mut_ptr(),
            &mut out_len,
            wrapped.len(),
            key.as_ptr(),
            key.len(),
        )
    };
    if ret != 1 {
        return Err(CryptoError::Internal);
    }
    Ok(out_len)
}

pub fn aes_kwp_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    let aes_key = BsslAesDecKey::new(kek, kek_to_key_size(kek.len())?)?;

    let mut out_len: usize = 0;
    // SAFETY: aes_key holds a valid AES key configured for decryption as
    // required by AES_unwrap_key_padded(). max_out is the length of key as
    // validated by the public keywrap module.
    let ret = unsafe {
        bssl_bare_sys::AES_unwrap_key_padded(
            aes_key.as_ptr(),
            key.as_mut_ptr(),
            &mut out_len,
            key.len(),
            wrapped.as_ptr(),
            wrapped.len(),
        )
    };
    if ret != 1 {
        // A zero return value indicates a failed integrity check, including
        // an invalid padding.
        return Err(CryptoError::SignatureVerificationFailure);
    }
    Ok(out_len)
}

fn kek_to_key_size(kek_len: usize) -> Result<SymBlockCipherAesKeySize, CryptoError> {
    match kek_len {
        16 => Ok(SymBlockCipherAesKeySize::Aes128),
        24 => Ok(SymBlockCipherAesKeySize::Aes192),
        32 => Ok(SymBlockCipherAesKeySize::Aes256),
        _ => Err(CryptoError::KeySize),
    }
}
