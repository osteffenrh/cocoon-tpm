// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! Pure Rust AES key wrapping, based on the RustCrypto `aes-kw` crate.

use aes_kw::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, typenum::U16};
use aes_kw::{AesKw, AesKwp};

use crate::CryptoError;

// The input length checks have already been conducted by the public
// keywrap module, the backend may rely on them.
pub fn aes_kw_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    match kek.len() {
        16 => kw_wrap::<aes_kw::aes::Aes128>(kek, key, wrapped),
        24 => kw_wrap::<aes_kw::aes::Aes192>(kek, key, wrapped),
        32 => kw_wrap::<aes_kw::aes::Aes256>(kek, key, wrapped),
        _ => Err(CryptoError::KeySize),
    }
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    match kek.len() {
        16 => kw_unwrap::<aes_kw::aes::Aes128>(kek, wrapped, key),
        24 => kw_unwrap::<aes_kw::aes::Aes192>(kek, wrapped, key),
        32 => kw_unwrap::<aes_kw::aes::Aes256>(kek, wrapped, key),
        _ => Err(CryptoError::KeySize),
    }
}

pub fn aes_kwp_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    match kek.len() {
        16 => kwp_wrap::<aes_kw::aes::Aes128>(kek, key, wrapped),
        24 => kwp_wrap::<aes_kw::aes::Aes192>(kek, key, wrapped),
        32 => kwp_wrap::<aes_kw::aes::Aes256>(kek, key, wrapped),
        _ => Err(CryptoError::KeySize),
    }
}

pub fn aes_kwp_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    match kek.len() {
        16 => kwp_unwrap::<aes_kw::aes::Aes128>(kek, wrapped, key),
        24 => kwp_unwrap::<aes_kw::aes::Aes192>(kek, wrapped, key),
        32 => kwp_unwrap::<aes_kw::aes::Aes256>(kek, wrapped, key),
        _ => Err(CryptoError::KeySize),
    }
}

fn kw_wrap<C>(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError>
where
    C: KeyInit + BlockCipherEncrypt<BlockSize = U16>,
{
    let kw = AesKw::<C>::new_from_slice(kek).map_err(|_| CryptoError::KeySize)?;
    let out = kw.wrap_key(key, wrapped).map_err(kw_error)?;
    Ok(out.len())
}

fn kw_unwrap<C>(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError>
where
    C: KeyInit + BlockCipherDecrypt<BlockSize = U16>,
{
    let kw = AesKw::<C>::new_from_slice(kek).map_err(|_| CryptoError::KeySize)?;
    let out = kw.unwrap_key(wrapped, key).map_err(kw_error)?;
    Ok(out.len())
}

fn kwp_wrap<C>(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError>
where
    C: KeyInit + BlockCipherEncrypt<BlockSize = U16>,
{
    let kwp = AesKwp::<C>::new_from_slice(kek).map_err(|_| CryptoError::KeySize)?;
    let out = kwp.wrap_key(key, wrapped).map_err(kw_error)?;
    Ok(out.len())
}

fn kwp_unwrap<C>(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError>
where
    C: KeyInit + BlockCipherDecrypt<BlockSize = U16>,
{
    let kwp = AesKwp::<C>::new_from_slice(kek).map_err(|_| CryptoError::KeySize)?;
    let out = kwp.unwrap_key(wrapped, key).map_err(kw_error)?;
    Ok(out.len())
}

fn kw_error(e: aes_kw::Error) -> CryptoError {
    match e {
        aes_kw::Error::InvalidDataSize | aes_kw::Error::InvalidOutputSize { .. } => CryptoError::InvalidMessageLength,
        aes_kw::Error::IntegrityCheckFailed => CryptoError::SignatureVerificationFailure,
    }
}
