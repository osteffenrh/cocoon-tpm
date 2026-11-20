// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! OpenSSL FFI backend for AEAD algorithms.
//!
//! Implemented through the EVP interface. Note that only the standard IV
//! length of 96 bits is supported, no `EVP_CTRL_AEAD_SET_IVLEN` is issued.

// Lifetimes are not obvious at first sight here, make them explicit.
#![allow(clippy::needless_lifetimes)]

use cocoon_tpm_ossl_bare_sys as ossl_bare_sys;

use super::error::ossl_get_error;
use crate::CryptoError;
use crate::aead::AeadAlg;
use crate::io_slices::{
    CryptoIoSlicesIter, CryptoIoSlicesMutIter, CryptoWalkableIoSlicesIter, CryptoWalkableIoSlicesMutIter,
};
use crate::utils_common::zeroize;
use core::{ffi, marker, ptr};

const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const AES256_GCM_KEY_LEN: usize = 32;

/// An AEAD instance, i.e. an algorithm together with a key.
///
/// The instance can get used for any number of one-shot
/// [encryption](AeadInstance::encrypt_in_place) and
/// [decryption](AeadInstance::decrypt_in_place) operations, also interleaved.
/// Each operation reinitializes the underlying OpenSSL `EVP_CIPHER_CTX` from
/// the stored key and the IV passed in.
///
/// The key material gets zeroized on drop if the `zeroize` Cargo feature is
/// enabled. The `EVP_CIPHER_CTX` is cleansed by
/// `EVP_CIPHER_CTX_free()` itself.
pub struct AeadInstance {
    ctx: ptr::NonNull<ossl_bare_sys::EVP_CIPHER_CTX>,
    key: zeroize::ZeroizingFlat<[u8; AES256_GCM_KEY_LEN]>,
    alg: AeadAlg,
}

// SAFETY: The instance owns the EVP_CIPHER_CTX exclusively and does not hold
// references into thread-local or global state. All operations take
// &mut self, so that no shared mutable access is possible.
unsafe impl marker::Send for AeadInstance {}

/// Verify that the source and destination buffer lists are of the same total
/// length and return that length.
fn check_lengths<'b, 'c, SI: CryptoWalkableIoSlicesIter<'b>, DI: CryptoWalkableIoSlicesMutIter<'c>>(
    src: &SI,
    dst: &DI,
) -> Result<usize, CryptoError> {
    let src_len = src.total_len()?;
    let dst_len = dst.total_len()?;
    if src_len != dst_len {
        return Err(CryptoError::InvalidMessageLength);
    }
    Ok(src_len)
}

/// Feed the paired source and destination buffer lists to the EVP cipher
/// context in lockstep, chunk by chunk.
fn encrypt_update_chunks<'b, 'c, SI: CryptoWalkableIoSlicesIter<'b>, DI: CryptoWalkableIoSlicesMutIter<'c>>(
    ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX,
    src: &mut SI,
    dst: &mut DI,
) -> Result<(), CryptoError> {
    loop {
        let dst_len = dst.next_slice_len()?;
        let src_len = src.next_slice_len()?;
        if dst_len == 0 && src_len == 0 {
            return Ok(());
        }
        // The total lengths have been verified to match upfront.
        if dst_len == 0 || src_len == 0 {
            return Err(CryptoError::Internal);
        }
        let chunk_len = dst_len.min(src_len);
        let dst_chunk = match dst.next_slice_mut(Some(chunk_len))? {
            Some(dst_chunk) => dst_chunk,
            None => return Err(CryptoError::Internal),
        };
        let src_chunk = match src.next_slice(Some(chunk_len))? {
            Some(src_chunk) => src_chunk,
            None => return Err(CryptoError::Internal),
        };
        debug_assert_eq!(src_chunk.len(), chunk_len);
        debug_assert_eq!(dst_chunk.len(), chunk_len);

        let inl = check_c_int_len(chunk_len)?;
        let mut outl: ffi::c_int = 0;
        // SAFETY: ctx is valid, src_chunk and dst_chunk are both of inl
        // bytes. The buffers must not partially overlap, fully identical
        // regions (in-place use) are supported by EVP_EncryptUpdate().
        if unsafe { ossl_bare_sys::EVP_EncryptUpdate(ctx, dst_chunk.as_mut_ptr(), &mut outl, src_chunk.as_ptr(), inl) }
            != 1
        {
            return Err(ossl_get_error());
        }
        debug_assert_eq!(outl as usize, chunk_len);
    }
}

/// Feed the paired source and destination buffer lists to the EVP cipher
/// context in lockstep, chunk by chunk.
fn decrypt_update_chunks<'b, 'c, SI: CryptoWalkableIoSlicesIter<'b>, DI: CryptoWalkableIoSlicesMutIter<'c>>(
    ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX,
    src: &mut SI,
    dst: &mut DI,
) -> Result<(), CryptoError> {
    loop {
        let dst_len = dst.next_slice_len()?;
        let src_len = src.next_slice_len()?;
        if dst_len == 0 && src_len == 0 {
            return Ok(());
        }
        // The total lengths have been verified to match upfront.
        if dst_len == 0 || src_len == 0 {
            return Err(CryptoError::Internal);
        }
        let chunk_len = dst_len.min(src_len);
        let dst_chunk = match dst.next_slice_mut(Some(chunk_len))? {
            Some(dst_chunk) => dst_chunk,
            None => return Err(CryptoError::Internal),
        };
        let src_chunk = match src.next_slice(Some(chunk_len))? {
            Some(src_chunk) => src_chunk,
            None => return Err(CryptoError::Internal),
        };
        debug_assert_eq!(src_chunk.len(), chunk_len);
        debug_assert_eq!(dst_chunk.len(), chunk_len);

        let inl = check_c_int_len(chunk_len)?;
        let mut outl: ffi::c_int = 0;
        // SAFETY: ctx is valid, src_chunk and dst_chunk are both of inl
        // bytes. The buffers must not partially overlap, fully identical
        // regions (in-place use) are supported by EVP_DecryptUpdate().
        if unsafe { ossl_bare_sys::EVP_DecryptUpdate(ctx, dst_chunk.as_mut_ptr(), &mut outl, src_chunk.as_ptr(), inl) }
            != 1
        {
            return Err(ossl_get_error());
        }
        debug_assert_eq!(outl as usize, chunk_len);
    }
}

/// Feed the message buffers to the EVP cipher context, chunk by chunk, in
/// place.
fn encrypt_update_in_place<'b, DI: CryptoIoSlicesMutIter<'b>>(
    ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX,
    buf: &mut DI,
) -> Result<(), CryptoError> {
    while let Some(chunk) = buf.next_slice_mut(None)? {
        let inl = check_c_int_len(chunk.len())?;
        let mut outl: ffi::c_int = 0;
        // SAFETY: ctx is valid, chunk is of inl bytes, in-place operation
        // (out == in) is supported by EVP_EncryptUpdate().
        if unsafe { ossl_bare_sys::EVP_EncryptUpdate(ctx, chunk.as_mut_ptr(), &mut outl, chunk.as_ptr(), inl) } != 1 {
            return Err(ossl_get_error());
        }
        debug_assert_eq!(outl as usize, chunk.len());
    }
    Ok(())
}

/// Feed the message buffers to the EVP cipher context, chunk by chunk, in
/// place.
fn decrypt_update_in_place<'b, DI: CryptoIoSlicesMutIter<'b>>(
    ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX,
    buf: &mut DI,
) -> Result<(), CryptoError> {
    while let Some(chunk) = buf.next_slice_mut(None)? {
        let inl = check_c_int_len(chunk.len())?;
        let mut outl: ffi::c_int = 0;
        // SAFETY: ctx is valid, chunk is of inl bytes, in-place operation
        // (out == in) is supported by EVP_DecryptUpdate().
        if unsafe { ossl_bare_sys::EVP_DecryptUpdate(ctx, chunk.as_mut_ptr(), &mut outl, chunk.as_ptr(), inl) } != 1 {
            return Err(ossl_get_error());
        }
        debug_assert_eq!(outl as usize, chunk.len());
    }
    Ok(())
}

impl AeadInstance {
    /// Create a new AEAD instance for the specified algorithm and key.
    ///
    /// # Arguments:
    ///
    /// * `alg` - The AEAD algorithm.
    /// * `key` - The key, of the length required by the algorithm.
    pub fn new(alg: AeadAlg, key: &[u8]) -> Result<Self, CryptoError> {
        let key: &[u8; AES256_GCM_KEY_LEN] = key.try_into().map_err(|_| CryptoError::KeySize)?;
        let ctx = unsafe { ossl_bare_sys::EVP_CIPHER_CTX_new() };
        let ctx = ptr::NonNull::new(ctx).ok_or(CryptoError::MemoryAllocationFailure)?;
        Ok(Self {
            ctx,
            key: zeroize::ZeroizingFlat::new(*key),
            alg,
        })
    }

    /// The IV length in bytes expected by all encryption and decryption
    /// operations.
    pub fn iv_len(&self) -> usize {
        match self.alg {
            AeadAlg::Aes256Gcm => GCM_IV_LEN,
        }
    }

    /// The authentication tag length in bytes generated by encryption and
    /// expected by decryption.
    pub fn tag_len(&self) -> usize {
        match self.alg {
            AeadAlg::Aes256Gcm => GCM_TAG_LEN,
        }
    }

    /// One-shot authenticated encryption.
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV, of length [`Self::iv_len()`].
    /// * `aad` - The additional authenticated data.
    /// * `ciphertext` - The destination buffers to write the ciphertext to.
    ///   Their total length must equal the total length of the `plaintext`
    ///   buffers. The plaintext and ciphertext buffers must not partially
    ///   overlap.
    /// * `plaintext` - The source buffers holding the message to encrypt.
    /// * `tag` - Output buffer of length [`Self::tag_len()`], receiving the
    ///   detached authentication tag.
    ///
    /// # Errors:
    ///
    /// * [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - The
    ///   total lengths of the `plaintext` and `ciphertext` buffer lists
    ///   differ.
    pub fn encrypt<'a, 'b, 'c, AI, SI, DI>(
        &mut self,
        iv: &[u8],
        mut aad: AI,
        mut ciphertext: DI,
        mut plaintext: SI,
        tag: &mut [u8],
    ) -> Result<(), CryptoError>
    where
        AI: CryptoIoSlicesIter<'a>,
        SI: CryptoWalkableIoSlicesIter<'b>,
        DI: CryptoWalkableIoSlicesMutIter<'c>,
    {
        self.check_iv_tag(iv, tag)?;
        check_lengths(&plaintext, &ciphertext)?;
        let ctx = self.ctx.as_ptr();

        // SAFETY: ctx is a valid EVP_CIPHER_CTX exclusively owned by self.
        // cipher is a valid EVP_CIPHER as returned by OpenSSL. key is of the
        // length expected by the cipher. Reinitializing the context from
        // cipher, key and IV resets any state left over from previous
        // operations.
        let cipher = self.evp_cipher();
        if unsafe { ossl_bare_sys::EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), self.key.as_ptr(), iv.as_ptr()) }
            != 1
        {
            return Err(ossl_get_error());
        }

        self.aad_update(ctx, &mut aad)?;
        encrypt_update_chunks(ctx, &mut plaintext, &mut ciphertext)?;
        self.encrypt_finish(ctx, tag)
    }

    /// One-shot in-place authenticated encryption with detached tag.
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV, of length [`Self::iv_len()`].
    /// * `aad` - The additional authenticated data.
    /// * `buf` - The source/destination buffers holding the message to
    ///   encrypt, to be replaced by the ciphertext in place.
    /// * `tag` - Output buffer of length [`Self::tag_len()`], receiving the
    ///   authentication tag.
    pub fn encrypt_in_place<'a, 'b, AI, DI>(
        &mut self,
        iv: &[u8],
        mut aad: AI,
        mut buf: DI,
        tag: &mut [u8],
    ) -> Result<(), CryptoError>
    where
        AI: CryptoIoSlicesIter<'a>,
        DI: CryptoIoSlicesMutIter<'b>,
    {
        self.check_iv_tag(iv, tag)?;
        let ctx = self.ctx.as_ptr();

        // SAFETY: see EVP_EncryptInit_ex() in encrypt().
        let cipher = self.evp_cipher();
        if unsafe { ossl_bare_sys::EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), self.key.as_ptr(), iv.as_ptr()) }
            != 1
        {
            return Err(ossl_get_error());
        }

        self.aad_update(ctx, &mut aad)?;
        encrypt_update_in_place(ctx, &mut buf)?;
        self.encrypt_finish(ctx, tag)
    }

    /// One-shot authenticated decryption.
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV, of length [`Self::iv_len()`].
    /// * `aad` - The additional authenticated data.
    /// * `plaintext` - The destination buffers to write the plaintext to.
    ///   Their total length must equal the total length of the `ciphertext`
    ///   buffers. The plaintext and ciphertext buffers must not partially
    ///   overlap.
    /// * `ciphertext` - The source buffers holding the message to decrypt.
    /// * `tag` - The detached authentication tag.
    ///
    /// # Errors:
    ///
    /// * [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - The
    ///   total lengths of the `plaintext` and `ciphertext` buffer lists
    ///   differ.
    /// * [`SignatureVerificationFailure`](CryptoError::SignatureVerificationFailure)
    ///   - Authentication of the ciphertext, tag or associated data failed.
    ///     The contents of the plaintext buffers are unspecified in this
    ///     case.
    pub fn decrypt<'a, 'b, 'c, AI, SI, DI>(
        &mut self,
        iv: &[u8],
        mut aad: AI,
        mut plaintext: DI,
        mut ciphertext: SI,
        tag: &[u8],
    ) -> Result<(), CryptoError>
    where
        AI: CryptoIoSlicesIter<'a>,
        SI: CryptoWalkableIoSlicesIter<'b>,
        DI: CryptoWalkableIoSlicesMutIter<'c>,
    {
        self.check_iv_tag(iv, tag)?;
        check_lengths(&ciphertext, &plaintext)?;
        let ctx = self.ctx.as_ptr();

        // SAFETY: see EVP_EncryptInit_ex() in encrypt().
        let cipher = self.evp_cipher();
        if unsafe { ossl_bare_sys::EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), self.key.as_ptr(), iv.as_ptr()) }
            != 1
        {
            return Err(ossl_get_error());
        }

        self.aad_update_decrypt(ctx, &mut aad)?;
        decrypt_update_chunks(ctx, &mut ciphertext, &mut plaintext)?;
        self.decrypt_finish(ctx, tag)
    }

    /// One-shot in-place authenticated decryption with detached tag.
    ///
    /// # Errors:
    ///
    /// * [`SignatureVerificationFailure`](CryptoError::SignatureVerificationFailure)
    ///   - Authentication of the ciphertext, tag or associated data failed.
    ///     The contents of the message buffers are unspecified in this case.
    ///
    /// # Arguments:
    ///
    /// * `iv` - The IV, of length [`Self::iv_len()`].
    /// * `aad` - The additional authenticated data.
    /// * `buf` - The source/destination buffers holding the ciphertext to
    ///   decrypt, to be replaced by the plaintext in place.
    /// * `tag` - The detached authentication tag.
    pub fn decrypt_in_place<'a, 'b, AI, DI>(
        &mut self,
        iv: &[u8],
        mut aad: AI,
        mut buf: DI,
        tag: &[u8],
    ) -> Result<(), CryptoError>
    where
        AI: CryptoIoSlicesIter<'a>,
        DI: CryptoIoSlicesMutIter<'b>,
    {
        self.check_iv_tag(iv, tag)?;
        let ctx = self.ctx.as_ptr();

        // SAFETY: see EVP_EncryptInit_ex() in encrypt().
        let cipher = self.evp_cipher();
        if unsafe { ossl_bare_sys::EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), self.key.as_ptr(), iv.as_ptr()) }
            != 1
        {
            return Err(ossl_get_error());
        }

        self.aad_update_decrypt(ctx, &mut aad)?;
        decrypt_update_in_place(ctx, &mut buf)?;
        self.decrypt_finish(ctx, tag)
    }

    /// Run the encryption finalization and retrieve the authentication tag.
    fn encrypt_finish(&mut self, ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX, tag: &mut [u8]) -> Result<(), CryptoError> {
        // GCM does not output any data at finalization, but calling
        // EVP_EncryptFinal_ex() is mandatory.
        let mut final_buf = zeroize::ZeroizingFlat::new([0u8; 16]);
        let mut outl: ffi::c_int = 0;
        // SAFETY: ctx is valid, final_buf is of at least one block size.
        if unsafe { ossl_bare_sys::EVP_EncryptFinal_ex(ctx, final_buf.as_mut_ptr(), &mut outl) } != 1 {
            return Err(ossl_get_error());
        }
        debug_assert_eq!(outl, 0);

        // SAFETY: ctx is valid, tag is of GCM_TAG_LEN bytes as negotiated
        // with the cipher.
        if unsafe {
            ossl_bare_sys::EVP_CIPHER_CTX_ctrl(
                ctx,
                ossl_bare_sys::EVP_CTRL_AEAD_GET_TAG,
                GCM_TAG_LEN as ffi::c_int,
                tag.as_mut_ptr().cast(),
            )
        } != 1
        {
            return Err(ossl_get_error());
        }

        Ok(())
    }

    /// Provide the authentication tag and run the decryption finalization,
    /// which verifies it.
    fn decrypt_finish(&mut self, ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX, tag: &[u8]) -> Result<(), CryptoError> {
        // Provide the tag before finalization. The const pointer needs to get
        // cast to a mutable one, EVP_CIPHER_CTX_ctrl() won't modify it for
        // EVP_CTRL_AEAD_SET_TAG.
        // SAFETY: ctx is valid, tag is of GCM_TAG_LEN bytes as negotiated
        // with the cipher.
        if unsafe {
            ossl_bare_sys::EVP_CIPHER_CTX_ctrl(
                ctx,
                ossl_bare_sys::EVP_CTRL_AEAD_SET_TAG,
                GCM_TAG_LEN as ffi::c_int,
                tag.as_ptr().cast_mut().cast(),
            )
        } != 1
        {
            return Err(ossl_get_error());
        }

        // EVP_DecryptFinal_ex() verifies the tag and returns zero on
        // mismatch.
        let mut final_buf = zeroize::ZeroizingFlat::new([0u8; 16]);
        let mut outl: ffi::c_int = 0;
        // SAFETY: ctx is valid, final_buf is of at least one block size.
        if unsafe { ossl_bare_sys::EVP_DecryptFinal_ex(ctx, final_buf.as_mut_ptr(), &mut outl) } != 1 {
            return Err(CryptoError::SignatureVerificationFailure);
        }
        debug_assert_eq!(outl, 0);

        Ok(())
    }

    fn check_iv_tag(&self, iv: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        if iv.len() != self.iv_len() {
            return Err(CryptoError::InvalidIV);
        }
        if tag.len() != self.tag_len() {
            return Err(CryptoError::InvalidParams);
        }
        Ok(())
    }

    fn evp_cipher(&self) -> *const ossl_bare_sys::EVP_CIPHER {
        // SAFETY: returning a static cipher handle, no preconditions.
        match self.alg {
            AeadAlg::Aes256Gcm => unsafe { ossl_bare_sys::EVP_aes_256_gcm() },
        }
    }

    fn aad_update<'a, AI: CryptoIoSlicesIter<'a>>(
        &self,
        ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX,
        mut aad: AI,
    ) -> Result<(), CryptoError> {
        while let Some(slice) = aad.next_slice(None)? {
            let aadl = check_c_int_len(slice.len())?;
            let mut outl: ffi::c_int = 0;
            // SAFETY: ctx is valid and in encryption state, slice is of aadl
            // bytes. The output buffer is NULL, as appropriate for AAD-only
            // updates.
            if unsafe { ossl_bare_sys::EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut outl, slice.as_ptr(), aadl) } != 1 {
                return Err(ossl_get_error());
            }
            // Note: both OpenSSL and BoringSSL report the AAD length in outl
            // here, no ciphertext is being produced.
        }
        Ok(())
    }

    fn aad_update_decrypt<'a, AI: CryptoIoSlicesIter<'a>>(
        &self,
        ctx: *mut ossl_bare_sys::EVP_CIPHER_CTX,
        mut aad: AI,
    ) -> Result<(), CryptoError> {
        while let Some(slice) = aad.next_slice(None)? {
            let aadl = check_c_int_len(slice.len())?;
            let mut outl: ffi::c_int = 0;
            // SAFETY: ctx is valid and in decryption state, slice is of aadl
            // bytes. The output buffer is NULL, as appropriate for AAD-only
            // updates.
            if unsafe { ossl_bare_sys::EVP_DecryptUpdate(ctx, ptr::null_mut(), &mut outl, slice.as_ptr(), aadl) } != 1 {
                return Err(ossl_get_error());
            }
            // Note: both OpenSSL and BoringSSL report the AAD length in outl
            // here, no ciphertext is being produced.
        }
        Ok(())
    }
}

fn check_c_int_len(len: usize) -> Result<ffi::c_int, CryptoError> {
    if len > ffi::c_int::MAX as usize {
        return Err(CryptoError::RequestTooBig);
    }
    Ok(len as ffi::c_int)
}

impl Drop for AeadInstance {
    fn drop(&mut self) {
        // SAFETY: self.ctx is a valid EVP_CIPHER_CTX exclusively owned by
        // self, which is getting dropped. EVP_CIPHER_CTX_free() cleanses the
        // context memory before releasing it.
        unsafe { ossl_bare_sys::EVP_CIPHER_CTX_free(self.ctx.as_ptr()) };
    }
}
