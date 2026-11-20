// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! OpenSSL FFI backend for AES key wrapping (RFC 3394 and RFC 5649),
//! implemented through the EVP wrap ciphers.
//!
//! EVP wrap ciphers require the `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` flag to get
//! set on the cipher context. Note that the whole wrapped output is already
//! emitted by `EVP_{Encrypt,Decrypt}Update()`, the subsequent
//! `EVP_{Encrypt,Decrypt}Final_ex()` calls don't output any data but still
//! need to get issued.

// Lifetimes are not obvious at first sight here, make them explicit.
#![allow(clippy::needless_lifetimes)]

use cocoon_tpm_ossl_bare_sys as ossl_bare_sys;

extern crate alloc;

use super::error::ossl_get_error;
use crate::{CryptoError, utils_common::zeroize};
use core::{ffi, ptr};

// The input length checks have already been conducted by the public
// keywrap module, the backend may rely on them.
pub fn aes_kw_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    let cipher = wrap_cipher(kek, false)?;
    let mut ctx = CipherCtx::new()?;
    ctx.wrap_allow();
    ctx.encrypt_init(cipher, kek)?;
    let outl = ctx.update_encrypt(wrapped, key)?;
    ctx.finalize(false)?;
    debug_assert_eq!(outl, key.len() + 8);
    Ok(outl)
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    let cipher = wrap_cipher(kek, false)?;
    let mut ctx = CipherCtx::new()?;
    ctx.wrap_allow();
    ctx.decrypt_init(cipher, kek)?;
    let outl = ctx.update_decrypt(key, wrapped)?;
    ctx.finalize(true)?;
    debug_assert_eq!(outl, wrapped.len() - 8);
    Ok(outl)
}

pub fn aes_kwp_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    let cipher = wrap_cipher(kek, true)?;
    let mut ctx = CipherCtx::new()?;
    ctx.wrap_allow();
    ctx.encrypt_init(cipher, kek)?;
    let outl = ctx.update_encrypt(wrapped, key)?;
    ctx.finalize(false)?;
    debug_assert!(outl >= key.len() + 8);
    Ok(outl)
}

pub fn aes_kwp_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    let cipher = wrap_cipher(kek, true)?;
    let mut ctx = CipherCtx::new()?;
    ctx.wrap_allow();
    ctx.decrypt_init(cipher, kek)?;

    // Decrypt into a scratch buffer rather than directly into the caller's
    // key buffer: OpenSSL up to and including 3.5.x cleanses the output
    // buffer over the full wrapped input length (instead of only the padded
    // plaintext length) when the integrity check fails, refer to
    // CRYPTO_128_unwrap_pad() in crypto/modes/wrap128.c. The overflow got
    // fixed in the OpenSSL development tree (commit b9a8b0e82805, not yet
    // part of any release), but the key buffer handed in by the caller may
    // well be smaller than the wrapped input.
    let mut scratch = zeroize::ZeroizingFlat::new(alloc::vec![0u8; wrapped.len()]);
    // The wrap ciphers with padding remove the padding during the update,
    // so the integrity check failure (including any padding failure)
    // surfaces here already.
    let outl = ctx.update_decrypt(&mut scratch, wrapped)?;
    ctx.finalize(true)?;
    debug_assert!(outl <= key.len());
    key[..outl].copy_from_slice(&scratch[..outl]);
    Ok(outl)
}

fn wrap_cipher(kek: &[u8], padded: bool) -> Result<*const ossl_bare_sys::EVP_CIPHER, CryptoError> {
    // SAFETY: All these functions return static, preconfigured cipher
    // handles, there are no preconditions.
    unsafe {
        Ok(match (kek.len(), padded) {
            (16, false) => ossl_bare_sys::EVP_aes_128_wrap(),
            (24, false) => ossl_bare_sys::EVP_aes_192_wrap(),
            (32, false) => ossl_bare_sys::EVP_aes_256_wrap(),
            (16, true) => ossl_bare_sys::EVP_aes_128_wrap_pad(),
            (24, true) => ossl_bare_sys::EVP_aes_192_wrap_pad(),
            (32, true) => ossl_bare_sys::EVP_aes_256_wrap_pad(),
            _ => return Err(CryptoError::KeySize),
        })
    }
}

fn check_c_int_len(len: usize) -> Result<ffi::c_int, CryptoError> {
    if len > ffi::c_int::MAX as usize {
        return Err(CryptoError::RequestTooBig);
    }
    Ok(len as ffi::c_int)
}

/// Small wrapper around an OpenSSL `EVP_CIPHER_CTX`, handling its lifetime.
struct CipherCtx {
    ctx: ptr::NonNull<ossl_bare_sys::EVP_CIPHER_CTX>,
}

impl CipherCtx {
    fn new() -> Result<Self, CryptoError> {
        // SAFETY: plain allocation, no preconditions.
        let ctx = unsafe { ossl_bare_sys::EVP_CIPHER_CTX_new() };
        let ctx = ptr::NonNull::new(ctx).ok_or(CryptoError::MemoryAllocationFailure)?;
        Ok(Self { ctx })
    }

    fn wrap_allow(&mut self) {
        // SAFETY: self.ctx is a valid EVP_CIPHER_CTX. The flag needs to get
        // set before the cipher initialization for wrap ciphers to get
        // accepted.
        unsafe {
            ossl_bare_sys::EVP_CIPHER_CTX_set_flags(self.ctx.as_ptr(), ossl_bare_sys::EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        };
    }

    fn encrypt_init(&mut self, cipher: *const ossl_bare_sys::EVP_CIPHER, kek: &[u8]) -> Result<(), CryptoError> {
        // SAFETY: self.ctx is a valid EVP_CIPHER_CTX, cipher a valid
        // EVP_CIPHER as returned by OpenSSL. The KEK length has already
        // been validated to match the selected cipher.
        if unsafe {
            ossl_bare_sys::EVP_EncryptInit_ex(self.ctx.as_ptr(), cipher, ptr::null_mut(), kek.as_ptr(), ptr::null())
        } != 1
        {
            return Err(ossl_get_error());
        }
        Ok(())
    }

    fn decrypt_init(&mut self, cipher: *const ossl_bare_sys::EVP_CIPHER, kek: &[u8]) -> Result<(), CryptoError> {
        // SAFETY: see encrypt_init().
        if unsafe {
            ossl_bare_sys::EVP_DecryptInit_ex(self.ctx.as_ptr(), cipher, ptr::null_mut(), kek.as_ptr(), ptr::null())
        } != 1
        {
            return Err(ossl_get_error());
        }
        Ok(())
    }

    /// Feed the whole input through the wrap cipher and return the number
    /// of output bytes written.
    fn update_encrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<usize, CryptoError> {
        let inl = check_c_int_len(input.len())?;
        let mut outl: ffi::c_int = 0;
        // SAFETY: self.ctx is a valid EVP_CIPHER_CTX in encryption state.
        // out and input are of matching lengths as validated by the public
        // keywrap module. Wrap ciphers emit the whole output in a single
        // update.
        if unsafe {
            ossl_bare_sys::EVP_EncryptUpdate(self.ctx.as_ptr(), out.as_mut_ptr(), &mut outl, input.as_ptr(), inl)
        } != 1
        {
            return Err(ossl_get_error());
        }
        debug_assert!(outl >= 0);
        Ok(outl as usize)
    }

    fn update_decrypt(&mut self, out: &mut [u8], input: &[u8]) -> Result<usize, CryptoError> {
        let inl = check_c_int_len(input.len())?;
        let mut outl: ffi::c_int = 0;
        // SAFETY: self.ctx is a valid EVP_CIPHER_CTX in decryption state.
        // out and input are of matching lengths as validated by the public
        // keywrap module. Wrap ciphers emit the whole output in a single
        // update. Failures, in particular integrity check failures, surface
        // here already.
        if unsafe {
            ossl_bare_sys::EVP_DecryptUpdate(self.ctx.as_ptr(), out.as_mut_ptr(), &mut outl, input.as_ptr(), inl)
        } != 1
        {
            // All structural input properties have been validated before, so
            // a failure at this point indicates a failed integrity check.
            return Err(CryptoError::SignatureVerificationFailure);
        }
        debug_assert!(outl >= 0);
        Ok(outl as usize)
    }

    fn finalize(&mut self, decrypting: bool) -> Result<(), CryptoError> {
        // Wrap ciphers don't output any data at finalization, but the call
        // is still mandatory.
        let mut final_buf = zeroize::ZeroizingFlat::new([0u8; 16]);
        let mut outl: ffi::c_int = 0;
        let ret = if decrypting {
            // SAFETY: self.ctx is a valid EVP_CIPHER_CTX in decryption
            // state, final_buf is of at least one block size.
            unsafe { ossl_bare_sys::EVP_DecryptFinal_ex(self.ctx.as_ptr(), final_buf.as_mut_ptr(), &mut outl) }
        } else {
            // SAFETY: self.ctx is a valid EVP_CIPHER_CTX in encryption
            // state, final_buf is of at least one block size.
            unsafe { ossl_bare_sys::EVP_EncryptFinal_ex(self.ctx.as_ptr(), final_buf.as_mut_ptr(), &mut outl) }
        };
        if ret != 1 {
            // All structural input properties have been validated before, so
            // a failure at this point indicates a failed integrity check.
            return Err(if decrypting {
                CryptoError::SignatureVerificationFailure
            } else {
                ossl_get_error()
            });
        }
        debug_assert_eq!(outl, 0);
        Ok(())
    }
}

impl Drop for CipherCtx {
    fn drop(&mut self) {
        // SAFETY: self.ctx is a valid EVP_CIPHER_CTX exclusively owned by
        // self, which is getting dropped. EVP_CIPHER_CTX_free() cleanses the
        // context memory before releasing it.
        unsafe { ossl_bare_sys::EVP_CIPHER_CTX_free(self.ctx.as_ptr()) };
    }
}
