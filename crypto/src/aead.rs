// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! Common interface to authenticated encryption with associated data (AEAD)
//! algorithm implementations.
//!
//! An [`AeadInstance`] binds an [`AeadAlg`] to a key and provides one-shot
//! authenticated encryption and decryption. All operations are performed under
//! a single IV, with the associated data (AAD) being authenticated but not
//! encrypted. The IV and tag lengths are fixed per algorithm, refer to the
//! [`AeadAlg`] variants.
//!
//! The AAD and the message data get passed in as *IO slice iterators*, in the
//! same manner as by the other interfaces provided by this crate: the AAD is
//! being authenticated only and gets consumed from a
//! [`CryptoIoSlicesIter`](crate::CryptoIoSlicesIter). For the operations with
//! separate source and destination buffers, both the source and the
//! destination are walkable IO slice iterators
//! ([`CryptoWalkableIoSlicesIter`](crate::CryptoWalkableIoSlicesIter) and
//! [`CryptoWalkableIoSlicesMutIter`](crate::CryptoWalkableIoSlicesMutIter)
//! respectively), with the total lengths of both having to match. The
//! in-place operations take the message buffers as a
//! [`CryptoIoSlicesMutIter`](crate::CryptoIoSlicesMutIter).
//!
//! The authentication tag is kept separate from the message buffers
//! ("detached tag", cf. RFC 5116): encryption writes it to a dedicated output
//! buffer, decryption takes it from an input buffer. Note that on decryption
//! failure, i.e. when the ciphertext, tag or associated data do not
//! authenticate, the contents of the message destination buffers are
//! unspecified.

/// AEAD algorithm identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    /// AES-256 in GCM mode as specified by NIST SP 800-38D and RFC 5116
    /// ("AEAD_AES_256_GCM").
    ///
    /// Uses a 96 bit IV and a 128 bit authentication tag.
    Aes256Gcm,
}

pub use super::backend::aead::*;

/// AES-256-GCM test vectors from the original GCM specification:
/// D. McGrew, J. Viega, "The Galois/Counter Mode of Operation (GCM)",
/// <http://www.cryptobarn.com/papers/gcm-spec.pdf>, test cases 13-16.
#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;
    use crate::CryptoError;
    use crate::utils_common::io_slices::{
        BuffersSliceIoSlicesIter, BuffersSliceIoSlicesMutIter, IoSlicesIterCommon as _, SingletonIoSlice,
        SingletonIoSliceMut,
    };

    struct TestVector {
        key: &'static [u8],
        iv: &'static [u8],
        aad: &'static [u8],
        plaintext: &'static [u8],
        ciphertext: &'static [u8],
        tag: &'static [u8],
    }

    impl TestVector {
        fn tc13() -> Self {
            Self {
                key: &[0u8; 32],
                iv: &[0u8; 12],
                aad: &[],
                plaintext: &[],
                ciphertext: &[],
                tag: &[
                    0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
                ],
            }
        }

        fn tc14() -> Self {
            Self {
                key: &[0u8; 32],
                iv: &[0u8; 12],
                aad: &[],
                plaintext: &[0u8; 16],
                ciphertext: &[
                    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
                ],
                tag: &[
                    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
                ],
            }
        }

        fn tc15() -> Self {
            Self {
                key: &[
                    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                ],
                iv: &[0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88],
                aad: &[],
                plaintext: &[
                    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
                ],
                ciphertext: &[
                    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
                    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
                    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
                    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
                ],
                tag: &[
                    0xeb, 0x9f, 0x79, 0x6c, 0x8d, 0x35, 0x6f, 0xc3, 0x1a, 0x84, 0x33, 0x88, 0x4b, 0x69, 0x6f, 0x4f,
                ],
            }
        }

        fn tc16() -> Self {
            Self {
                aad: &[
                    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xab, 0xad, 0xda, 0xd2,
                ],
                tag: &[
                    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
                ],
                ..Self::tc15()
            }
        }
    }

    fn run_vector(tv: &TestVector) {
        let mut aead = AeadInstance::new(AeadAlg::Aes256Gcm, tv.key).unwrap();

        // One-shot encryption with separate source and destination buffers.
        let mut ciphertext = vec![0u8; tv.plaintext.len()];
        let mut tag = vec![0u8; aead.tag_len()];
        aead.encrypt(
            tv.iv,
            SingletonIoSlice::new(tv.aad).map_infallible_err(),
            SingletonIoSliceMut::new(&mut ciphertext).map_infallible_err(),
            SingletonIoSlice::new(tv.plaintext).map_infallible_err(),
            &mut tag,
        )
        .unwrap();
        assert_eq!(&ciphertext, tv.ciphertext);
        assert_eq!(&tag, tv.tag);

        // In-place encryption, detached tag.
        let mut buf = tv.plaintext.to_vec();
        let mut tag = vec![0u8; aead.tag_len()];
        aead.encrypt_in_place(
            tv.iv,
            SingletonIoSlice::new(tv.aad).map_infallible_err(),
            SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
            &mut tag,
        )
        .unwrap();
        assert_eq!(&buf, tv.ciphertext);
        assert_eq!(&tag, tv.tag);

        // One-shot decryption with separate source and destination buffers.
        let mut plaintext = vec![0u8; tv.ciphertext.len()];
        aead.decrypt(
            tv.iv,
            SingletonIoSlice::new(tv.aad).map_infallible_err(),
            SingletonIoSliceMut::new(&mut plaintext).map_infallible_err(),
            SingletonIoSlice::new(&ciphertext).map_infallible_err(),
            &tag,
        )
        .unwrap();
        assert_eq!(&plaintext, tv.plaintext);

        // In-place decryption, detached tag.
        let mut buf = tv.ciphertext.to_vec();
        aead.decrypt_in_place(
            tv.iv,
            SingletonIoSlice::new(tv.aad).map_infallible_err(),
            SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
            &tag,
        )
        .unwrap();
        assert_eq!(&buf, tv.plaintext);

        // Tampered tag must fail.
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 1;
        let mut buf = tv.ciphertext.to_vec();
        assert!(matches!(
            aead.decrypt_in_place(
                tv.iv,
                SingletonIoSlice::new(tv.aad).map_infallible_err(),
                SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
                &bad_tag
            ),
            Err(CryptoError::SignatureVerificationFailure)
        ));

        // Tampered ciphertext must fail.
        if !tv.ciphertext.is_empty() {
            let mut bad_ciphertext = ciphertext.clone();
            bad_ciphertext[0] ^= 1;
            let mut plaintext = vec![0u8; tv.plaintext.len()];
            assert!(matches!(
                aead.decrypt(
                    tv.iv,
                    SingletonIoSlice::new(tv.aad).map_infallible_err(),
                    SingletonIoSliceMut::new(&mut plaintext).map_infallible_err(),
                    SingletonIoSlice::new(&bad_ciphertext).map_infallible_err(),
                    &tag
                ),
                Err(CryptoError::SignatureVerificationFailure)
            ));
        }

        // Tampered AAD must fail.
        if !tv.aad.is_empty() {
            let mut bad_aad = tv.aad.to_vec();
            bad_aad[0] ^= 1;
            let mut buf = tv.ciphertext.to_vec();
            assert!(matches!(
                aead.decrypt_in_place(
                    tv.iv,
                    SingletonIoSlice::new(&bad_aad).map_infallible_err(),
                    SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
                    &tag
                ),
                Err(CryptoError::SignatureVerificationFailure)
            ));
        }
    }

    #[test]
    fn test_aead_aes256gcm_tc13() {
        run_vector(&TestVector::tc13());
    }

    #[test]
    fn test_aead_aes256gcm_tc14() {
        run_vector(&TestVector::tc14());
    }

    #[test]
    fn test_aead_aes256gcm_tc15() {
        run_vector(&TestVector::tc15());
    }

    #[test]
    fn test_aead_aes256gcm_tc16() {
        run_vector(&TestVector::tc16());
    }

    #[test]
    fn test_aead_scattered_buffers() {
        // Encrypt and decrypt with the AAD and the message data spread over
        // multiple buffers. The results must not differ from the contiguous
        // case.
        let tv = TestVector::tc16();
        let mut aead = AeadInstance::new(AeadAlg::Aes256Gcm, tv.key).unwrap();

        let (aad0, aad1) = tv.aad.split_at(tv.aad.len() / 2);
        let aad = [aad0, aad1];

        let (pt0, pt_rest) = tv.plaintext.split_at(tv.plaintext.len() / 3);
        let (pt1, pt2) = pt_rest.split_at(pt_rest.len() / 2);
        assert!(!pt2.is_empty());
        let src = [pt0, pt1, pt2];

        let mut ciphertext = vec![0u8; tv.plaintext.len()];
        let split = ciphertext.len() / 4;
        let (ct0, ct_rest) = ciphertext.split_at_mut(split);
        let split = ct_rest.len() / 3;
        let (ct1, ct2) = ct_rest.split_at_mut(split);
        assert!(!ct2.is_empty());
        let mut dst = [ct0, ct1, ct2];

        let mut tag = [0u8; 16];
        aead.encrypt(
            tv.iv,
            BuffersSliceIoSlicesIter::new(&aad).map_infallible_err(),
            BuffersSliceIoSlicesMutIter::new(&mut dst).map_infallible_err(),
            BuffersSliceIoSlicesIter::new(&src).map_infallible_err(),
            &mut tag,
        )
        .unwrap();
        assert_eq!(&ciphertext, tv.ciphertext);
        assert_eq!(&tag, tv.tag);

        // Scattered in-place decryption.
        let mut buf = tv.ciphertext.to_vec();
        let split = buf.len() / 2;
        let (buf0, buf_rest) = buf.split_at_mut(split);
        let split = buf_rest.len() / 2;
        let (buf1, buf2) = buf_rest.split_at_mut(split);
        assert!(!buf2.is_empty());
        let mut bufs = [buf0, buf1, buf2];
        aead.decrypt_in_place(
            tv.iv,
            BuffersSliceIoSlicesIter::new(&aad).map_infallible_err(),
            BuffersSliceIoSlicesMutIter::new(&mut bufs).map_infallible_err(),
            &tag,
        )
        .unwrap();
        assert_eq!(&buf, tv.plaintext);

        // Scattered one-shot decryption with scattered source and
        // destination buffers.
        let mut plaintext = vec![0u8; tv.ciphertext.len()];
        let (pt0, pt_rest) = plaintext.split_at_mut(7);
        let (pt1, pt2) = pt_rest.split_at_mut(9);
        assert!(!pt2.is_empty());
        let mut dst = [pt0, pt1, pt2];
        aead.decrypt(
            tv.iv,
            BuffersSliceIoSlicesIter::new(&aad).map_infallible_err(),
            BuffersSliceIoSlicesMutIter::new(&mut dst).map_infallible_err(),
            BuffersSliceIoSlicesIter::new(&[&ciphertext[..20], &ciphertext[20..]]).map_infallible_err(),
            &tag,
        )
        .unwrap();
        assert_eq!(&plaintext, tv.plaintext);
    }

    #[test]
    fn test_aead_wrong_key_size() {
        assert!(matches!(
            AeadInstance::new(AeadAlg::Aes256Gcm, &[0u8; 16]),
            Err(CryptoError::KeySize)
        ));
    }

    #[test]
    fn test_aead_wrong_iv_len() {
        let mut aead = AeadInstance::new(AeadAlg::Aes256Gcm, &[0u8; 32]).unwrap();
        let mut tag = [0u8; 16];
        let mut buf = [0u8; 16];
        assert!(matches!(
            aead.encrypt_in_place(
                &[0u8; 11],
                SingletonIoSlice::new(&[]).map_infallible_err(),
                SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
                &mut tag
            ),
            Err(CryptoError::InvalidIV)
        ));
    }

    #[test]
    fn test_aead_wrong_tag_len() {
        let mut aead = AeadInstance::new(AeadAlg::Aes256Gcm, &[0u8; 32]).unwrap();
        let mut buf = [0u8; 16];
        assert!(matches!(
            aead.encrypt_in_place(
                &[0u8; 12],
                SingletonIoSlice::new(&[]).map_infallible_err(),
                SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
                &mut [0u8; 15]
            ),
            Err(CryptoError::InvalidParams)
        ));
    }

    #[test]
    fn test_aead_mismatched_buffer_len() {
        let mut aead = AeadInstance::new(AeadAlg::Aes256Gcm, &[0u8; 32]).unwrap();
        let mut ciphertext = [0u8; 15];
        let mut tag = [0u8; 16];
        assert!(matches!(
            aead.encrypt(
                &[0u8; 12],
                SingletonIoSlice::new(&[]).map_infallible_err(),
                SingletonIoSliceMut::new(&mut ciphertext).map_infallible_err(),
                SingletonIoSlice::new(&[0u8; 16]).map_infallible_err(),
                &mut tag
            ),
            Err(CryptoError::InvalidMessageLength)
        ));
    }

    #[test]
    fn test_aead_instance_reuse() {
        // Multiple operations with a single instance must yield the same
        // results, also when interleaving encryption and decryption.
        let tv = TestVector::tc16();
        let mut aead = AeadInstance::new(AeadAlg::Aes256Gcm, tv.key).unwrap();

        for _ in 0..3 {
            let mut buf = tv.plaintext.to_vec();
            let mut tag = [0u8; 16];
            aead.encrypt_in_place(
                tv.iv,
                SingletonIoSlice::new(tv.aad).map_infallible_err(),
                SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
                &mut tag,
            )
            .unwrap();
            assert_eq!(&buf, tv.ciphertext);
            assert_eq!(&tag, tv.tag);

            let mut buf = tv.ciphertext.to_vec();
            aead.decrypt_in_place(
                tv.iv,
                SingletonIoSlice::new(tv.aad).map_infallible_err(),
                SingletonIoSliceMut::new(&mut buf).map_infallible_err(),
                &tag,
            )
            .unwrap();
            assert_eq!(&buf, tv.plaintext);
        }
    }
}
