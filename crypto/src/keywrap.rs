// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat
// Author: Oliver Steffen <osteffen@redhat.com>

//! Common interface to AES key wrapping implementations.
//!
//! Implements [AES Key Wrap (KW), RFC 3394][kw] and [AES Key Wrap with Padding
//! (KWP), RFC 5649][kwp], as also specified by NIST SP 800-38F. Key material
//! gets wrapped under an AES key encryption key (KEK) of 128, 192 or 256
//! bits.
//!
//! Note that KW requires the key data to be a multiple of 64 bits and at
//! least 128 bits long, whereas KWP accepts arbitrary key data lengths from
//! one byte up. Also note that KW and KWP are *not* interoperable: KW uses
//! the initial value `A6A6A6A6A6A6A6A6` while KWP uses the alternative
//! initial value `A65959A6 || length`, so that the two cannot get confused
//! with each other, refer to RFC 5649, section 3.
//!
//! Both variants include an integrity check: unwrapping fails with
//! [`SignatureVerificationFailure`](CryptoError::SignatureVerificationFailure)
//! if the wrapped key data is invalid or tampered with.
//!
//! Unlike the message-data parameters of some of the other interfaces of
//! this crate (e.g. [`hash`](crate::hash) or
//! [`symcipher`](crate::symcipher)), the key data doesn't get passed in as
//! *IO slice iterators* here, but as plain slices: KW/KWP are atomic
//! operations over the key data as a whole, which also undergoes a length
//! transformation (the padding), and none of the backends supports
//! processing the input incrementally.
//!
//! [kw]: https://www.rfc-editor.org/rfc/rfc3394
//! [kwp]: https://www.rfc-editor.org/rfc/rfc5649

use crate::CryptoError;

/// Semiblock size in bytes, the granularity at which KW and KWP operate.
const SEMIBLOCK_LEN: usize = 8;

/// Wrap `key` under the key encryption key `kek` with AES-KW (RFC 3394).
///
/// The length of `key` must be a multiple of 64 bits and at least 128 bits.
/// `wrapped` must be large enough to hold `key.len() + 8` bytes.
///
/// # Errors:
///
/// * [`KeySize`](CryptoError::KeySize) - Invalid KEK length, must be 16, 24
///   or 32 bytes.
/// * [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - `key`
///   length not a multiple of 8 and at least 16 bytes, or `wrapped` too
///   small.
///
/// # Arguments:
///
/// * `kek` - The key encryption key.
/// * `key` - The key data to wrap.
/// * `wrapped` - Output buffer, receiving the wrapped key data.
///
/// # Returns:
///
/// The number of bytes written to `wrapped`, `key.len() + 8`.
pub fn aes_kw_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    check_kek(kek)?;
    if key.len() < 2 * SEMIBLOCK_LEN || key.len() % SEMIBLOCK_LEN != 0 {
        return Err(CryptoError::InvalidMessageLength);
    }
    if wrapped.len() < key.len() + SEMIBLOCK_LEN {
        return Err(CryptoError::InvalidMessageLength);
    }
    super::backend::keywrap::aes_kw_wrap(kek, key, wrapped)
}

/// Unwrap `wrapped` under the key encryption key `kek` with AES-KW
/// (RFC 3394).
///
/// The length of `wrapped` must be a multiple of 64 bits and at least 192
/// bits. `key` must be large enough to hold `wrapped.len() - 8` bytes.
///
/// # Errors:
///
/// * [`KeySize`](CryptoError::KeySize) - Invalid KEK length, must be 16, 24
///   or 32 bytes.
/// * [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - `wrapped`
///   length not a multiple of 8 and at least 24 bytes, or `key` too small.
/// * [`SignatureVerificationFailure`](CryptoError::SignatureVerificationFailure)
///   - The integrity check failed, the wrapped key data is invalid or has
///   been tampered with.
///
/// # Arguments:
///
/// * `kek` - The key encryption key.
/// * `wrapped` - The wrapped key data.
/// * `key` - Output buffer, receiving the unwrapped key data.
///
/// # Returns:
///
/// The number of bytes written to `key`, `wrapped.len() - 8`.
pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    check_kek(kek)?;
    if wrapped.len() < 3 * SEMIBLOCK_LEN || wrapped.len() % SEMIBLOCK_LEN != 0 {
        return Err(CryptoError::InvalidMessageLength);
    }
    if key.len() < wrapped.len() - SEMIBLOCK_LEN {
        return Err(CryptoError::InvalidMessageLength);
    }
    super::backend::keywrap::aes_kw_unwrap(kek, wrapped, key)
}

/// Wrap `key` under the key encryption key `kek` with AES-KWP (RFC 5649).
///
/// The length of `key` can be arbitrary, from one byte up to 2^32 - 1.
/// `wrapped` must be large enough to hold the padded key data plus the
/// 8-byte integrity check value, i.e. `key.len().div_ceil(8) * 8 + 8` bytes.
///
/// # Errors:
///
/// * [`KeySize`](CryptoError::KeySize) - Invalid KEK length, must be 16, 24
///   or 32 bytes.
/// * [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - `key`
///   empty or too long, or `wrapped` too small.
///
/// # Arguments:
///
/// * `kek` - The key encryption key.
/// * `key` - The key data to wrap.
/// * `wrapped` - Output buffer, receiving the wrapped key data.
///
/// # Returns:
///
/// The number of bytes written to `wrapped`.
pub fn aes_kwp_wrap(kek: &[u8], key: &[u8], wrapped: &mut [u8]) -> Result<usize, CryptoError> {
    check_kek(kek)?;
    let expected_len = kwp_wrapped_len(key.len())?;
    if wrapped.len() < expected_len {
        return Err(CryptoError::InvalidMessageLength);
    }
    super::backend::keywrap::aes_kwp_wrap(kek, key, wrapped)
}

/// Unwrap `wrapped` under the key encryption key `kek` with AES-KWP
/// (RFC 5649).
///
/// The length of `wrapped` must be a multiple of 64 bits and at least 128
/// bits. `key` must be large enough to hold the unwrapped key data, i.e.
/// `wrapped.len() - 8` bytes in the worst case.
///
/// # Errors:
///
/// * [`KeySize`](CryptoError::KeySize) - Invalid KEK length, must be 16, 24
///   or 32 bytes.
/// * [`InvalidMessageLength`](CryptoError::InvalidMessageLength) - `wrapped`
///   length not a multiple of 8 and at least 16 bytes, or `key` too small.
/// * [`SignatureVerificationFailure`](CryptoError::SignatureVerificationFailure)
///   - The integrity check failed, the wrapped key data is invalid or has
///   been tampered with.
///
/// # Arguments:
///
/// * `kek` - The key encryption key.
/// * `wrapped` - The wrapped key data.
/// * `key` - Output buffer, receiving the unwrapped key data.
///
/// # Returns:
///
/// The number of bytes written to `key`.
pub fn aes_kwp_unwrap(kek: &[u8], wrapped: &[u8], key: &mut [u8]) -> Result<usize, CryptoError> {
    check_kek(kek)?;
    if wrapped.len() < 2 * SEMIBLOCK_LEN || wrapped.len() % SEMIBLOCK_LEN != 0 {
        return Err(CryptoError::InvalidMessageLength);
    }
    if key.len() < wrapped.len() - SEMIBLOCK_LEN {
        return Err(CryptoError::InvalidMessageLength);
    }
    super::backend::keywrap::aes_kwp_unwrap(kek, wrapped, key)
}

/// Check that the KEK length is a valid AES key length.
fn check_kek(kek: &[u8]) -> Result<(), CryptoError> {
    if !matches!(kek.len(), 16 | 24 | 32) {
        return Err(CryptoError::KeySize);
    }
    Ok(())
}

/// The length of the KWP output wrapping a key of `key_len` bytes.
fn kwp_wrapped_len(key_len: usize) -> Result<usize, CryptoError> {
    // The 32-bit MLI field in the alternative initial value limits the key
    // length, refer to RFC 5649, section 3.
    if key_len == 0 || key_len > u32::MAX as usize {
        return Err(CryptoError::InvalidMessageLength);
    }
    Ok(key_len.div_ceil(SEMIBLOCK_LEN) * SEMIBLOCK_LEN + SEMIBLOCK_LEN)
}

/// Test vectors from RFC 3394, section 4 and RFC 5649, section 6, verified
/// against an independent implementation.
#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    struct KwVector {
        kek: &'static [u8],
        key: &'static [u8],
        wrapped: &'static [u8],
    }

    fn kw_vectors() -> alloc::vec::Vec<KwVector> {
        let kek128: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let kek192: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let kek256: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        // Note the different key data patterns used by the RFC for lengths
        // beyond 128 bits.
        let key128: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let key192: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let key256: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        vec![
            // RFC 3394, section 4.1.
            KwVector {
                kek: kek128,
                key: key128,
                wrapped: &[
                    0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
                    0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
                ],
            },
            // RFC 3394, section 4.2.
            KwVector {
                kek: kek192,
                key: key128,
                wrapped: &[
                    0x96, 0x77, 0x8b, 0x25, 0xae, 0x6c, 0xa4, 0x35, 0xf9, 0x2b, 0x5b, 0x97, 0xc0, 0x50, 0xae, 0xd2,
                    0x46, 0x8a, 0xb8, 0xa1, 0x7a, 0xd8, 0x4e, 0x5d,
                ],
            },
            // RFC 3394, section 4.3.
            KwVector {
                kek: kek256,
                key: key128,
                wrapped: &[
                    0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x05, 0x81, 0x8a, 0x2a,
                    0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7,
                ],
            },
            // RFC 3394, section 4.4.
            KwVector {
                kek: kek192,
                key: key192,
                wrapped: &[
                    0x03, 0x1d, 0x33, 0x26, 0x4e, 0x15, 0xd3, 0x32, 0x68, 0xf2, 0x4e, 0xc2, 0x60, 0x74, 0x3e, 0xdc,
                    0xe1, 0xc6, 0xc7, 0xdd, 0xee, 0x72, 0x5a, 0x93, 0x6b, 0xa8, 0x14, 0x91, 0x5c, 0x67, 0x62, 0xd2,
                ],
            },
            // RFC 3394, section 4.5.
            KwVector {
                kek: kek256,
                key: key192,
                wrapped: &[
                    0xa8, 0xf9, 0xbc, 0x16, 0x12, 0xc6, 0x8b, 0x3f, 0xf6, 0xe6, 0xf4, 0xfb, 0xe3, 0x0e, 0x71, 0xe4,
                    0x76, 0x9c, 0x8b, 0x80, 0xa3, 0x2c, 0xb8, 0x95, 0x8c, 0xd5, 0xd1, 0x7d, 0x6b, 0x25, 0x4d, 0xa1,
                ],
            },
            // RFC 3394, section 4.6.
            KwVector {
                kek: kek256,
                key: key256,
                wrapped: &[
                    0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87, 0xf8, 0x26,
                    0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7, 0x1a, 0x99, 0xf4, 0x3b,
                    0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21,
                ],
            },
        ]
    }

    fn run_kw_vector(tv: &KwVector) {
        // Wrap.
        let mut wrapped = vec![0u8; tv.key.len() + 8];
        let n = aes_kw_wrap(tv.kek, tv.key, &mut wrapped).unwrap();
        assert_eq!(n, tv.wrapped.len());
        assert_eq!(&wrapped[..n], tv.wrapped);

        // Unwrap.
        let mut key = vec![0u8; tv.wrapped.len() - 8];
        let n = aes_kw_unwrap(tv.kek, tv.wrapped, &mut key).unwrap();
        assert_eq!(n, tv.key.len());
        assert_eq!(&key[..n], tv.key);

        // Tampered wrapped key data must fail the integrity check.
        let mut bad = tv.wrapped.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut key = vec![0u8; tv.wrapped.len() - 8];
        assert!(matches!(
            aes_kw_unwrap(tv.kek, &bad, &mut key),
            Err(CryptoError::SignatureVerificationFailure)
        ));
    }

    #[test]
    fn test_aes_kw_rfc3394() {
        for tv in kw_vectors() {
            run_kw_vector(&tv);
        }
    }

    #[test]
    fn test_aes_kw_length_errors() {
        let kek = [0u8; 32];
        // Key data too short / not a multiple of 64 bits.
        let mut wrapped = [0u8; 40];
        assert!(matches!(
            aes_kw_wrap(&kek, &[0u8; 8], &mut wrapped),
            Err(CryptoError::InvalidMessageLength)
        ));
        assert!(matches!(
            aes_kw_wrap(&kek, &[0u8; 17], &mut wrapped),
            Err(CryptoError::InvalidMessageLength)
        ));
        // Output buffer too small.
        let mut wrapped = [0u8; 23];
        assert!(matches!(
            aes_kw_wrap(&kek, &[0u8; 16], &mut wrapped),
            Err(CryptoError::InvalidMessageLength)
        ));
        // Wrapped input too short.
        let mut key = [0u8; 8];
        assert!(matches!(
            aes_kw_unwrap(&kek, &[0u8; 16], &mut key),
            Err(CryptoError::InvalidMessageLength)
        ));
        // Invalid KEK size.
        assert!(matches!(
            aes_kw_wrap(&[0u8; 15], &[0u8; 16], &mut wrapped),
            Err(CryptoError::KeySize)
        ));
    }

    struct KwpVector {
        kek: &'static [u8],
        key: &'static [u8],
        wrapped: &'static [u8],
    }

    fn kwp_vectors() -> alloc::vec::Vec<KwpVector> {
        // RFC 5649, section 6, first example: 20 octets of key data under a
        // 192-bit KEK.
        let kek192: &[u8] = &[
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e, 0xa1, 0xae, 0x83,
            0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        vec![
            KwpVector {
                kek: kek192,
                key: &[
                    0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
                    0x50, 0x68, 0xf7, 0x38,
                ],
                wrapped: &[
                    0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22, 0x48, 0xee,
                    0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73, 0xfa, 0x54, 0x3b, 0x6a,
                ],
            },
            // RFC 5649, section 6, second example: 7 octets of key data
            // under the same KEK.
            KwpVector {
                kek: kek192,
                key: &[0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69],
                wrapped: &[
                    0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2, 0x4f,
                ],
            },
        ]
    }

    fn run_kwp_vector(tv: &KwpVector) {
        // Wrap.
        let mut wrapped = vec![0u8; tv.key.len() + 15];
        let n = aes_kwp_wrap(tv.kek, tv.key, &mut wrapped).unwrap();
        assert_eq!(&wrapped[..n], tv.wrapped);

        // Unwrap.
        let mut key = vec![0u8; tv.wrapped.len() - 8];
        let n = aes_kwp_unwrap(tv.kek, tv.wrapped, &mut key).unwrap();
        assert_eq!(n, tv.key.len());
        assert_eq!(&key[..n], tv.key);

        // Tampered wrapped key data must fail the integrity check.
        let mut bad = tv.wrapped.to_vec();
        bad[0] ^= 1;
        let mut key = vec![0u8; tv.wrapped.len() - 8];
        assert!(matches!(
            aes_kwp_unwrap(tv.kek, &bad, &mut key),
            Err(CryptoError::SignatureVerificationFailure)
        ));
    }

    #[test]
    fn test_aes_kwp_rfc5649() {
        for tv in kwp_vectors() {
            run_kwp_vector(&tv);
        }
    }

    #[test]
    fn test_aes_kwp_roundtrip() {
        // Round-trip over key data lengths exercising the padding,
        // including the single-block special case for lengths <= 8.
        let kek = [7u8; 32];
        for key_len in [1usize, 2, 5, 7, 8, 9, 15, 16, 17, 24, 32, 33, 64] {
            let key: alloc::vec::Vec<u8> = (0..key_len).map(|i| (i * 7 % 251) as u8).collect();

            let mut wrapped = vec![0u8; key_len + 15];
            let wn = aes_kwp_wrap(&kek, &key, &mut wrapped).unwrap();

            let mut unwrapped = vec![0u8; wn - 8];
            let un = aes_kwp_unwrap(&kek, &wrapped[..wn], &mut unwrapped).unwrap();
            assert_eq!(un, key_len);
            assert_eq!(&unwrapped[..un], &key);
        }
    }

    #[test]
    fn test_aes_kwp_length_errors() {
        let kek = [0u8; 16];
        // Empty key data.
        let mut wrapped = [0u8; 16];
        assert!(matches!(
            aes_kwp_wrap(&kek, &[], &mut wrapped),
            Err(CryptoError::InvalidMessageLength)
        ));
        // Output buffer too small for the padded key data.
        let mut wrapped = [0u8; 22];
        assert!(matches!(
            aes_kwp_wrap(&kek, &[0u8; 17], &mut wrapped),
            Err(CryptoError::InvalidMessageLength)
        ));
        // Wrapped input not a multiple of 64 bits.
        let mut key = [0u8; 16];
        assert!(matches!(
            aes_kwp_unwrap(&kek, &[0u8; 17], &mut key),
            Err(CryptoError::InvalidMessageLength)
        ));
        // Invalid KEK size.
        assert!(matches!(
            aes_kwp_wrap(&[0u8; 12], &[0u8; 16], &mut wrapped),
            Err(CryptoError::KeySize)
        ));
    }

    #[test]
    fn test_aes_kw_kwp_not_interoperable() {
        // KW and KWP use different initial values and must reject each
        // other's output, refer to RFC 5649, section 3.
        let kek = [3u8; 32];
        let key = [5u8; 32];

        let mut wrapped = vec![0u8; 40];
        let wn = aes_kw_wrap(&kek, &key, &mut wrapped).unwrap();
        let mut out = vec![0u8; wn - 8];
        assert!(matches!(
            aes_kwp_unwrap(&kek, &wrapped[..wn], &mut out),
            Err(CryptoError::SignatureVerificationFailure)
        ));

        let wn = aes_kwp_wrap(&kek, &key, &mut wrapped).unwrap();
        let mut out = vec![0u8; wn - 8];
        assert!(matches!(
            aes_kw_unwrap(&kek, &wrapped[..wn], &mut out),
            Err(CryptoError::SignatureVerificationFailure)
        ));
    }
}
