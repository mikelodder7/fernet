/*
 * Copyright 2019 Michael Lodder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */
//! This crate implements Fernet tokens
//! but adds additional formats that take advantage of newer crypto primitives
#[deny(warnings, unused_import_braces, unused_qualifications, trivial_casts, trivial_numeric_casts)]

//#[cfg(feature = "version1")]
#[macro_use]
extern crate arrayref;

pub mod error;
#[cfg(feature = "version1")]
mod aead_aes_cbc_hmac;
#[cfg(feature = "version2")]
extern crate aes_gcm;
#[cfg(feature = "version3")]
extern crate chacha20poly1305;

use aead::{
    Aead,
    NewAead,
    Payload,
    generic_array::{
        GenericArray,
        typenum::{
            Unsigned,
            U16, U32
        }
    }
};
#[cfg(feature = "version1")]
use aead_aes_cbc_hmac::Aes128CbcHmac256;
#[cfg(feature = "version2")]
use aes_gcm::Aes128Gcm;
#[cfg(feature = "version3")]
use chacha20poly1305::XChaCha20Poly1305;

use rand::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::*;
use zeroize::Zeroize;

macro_rules! token_impl {
    ($name: ident, $keysize:ident, $version:expr) => {
        impl $name {
            pub const VERSION: u8 = $version;

            pub fn new() -> Self {
                let mut rng = thread_rng();
                let mut key = vec![0u8; $keysize::to_usize()];
                rng.fill_bytes(key.as_mut_slice());
                let key = GenericArray::clone_from_slice(&key);
                let encoder = Encoder::new(Self::VERSION, &key);
                Self { key, encoder }
            }

            pub fn new_with_key(key: &GenericArray<u8, $keysize>) -> Self {
                Self { key: key.clone(), encoder: Encoder::new(Self::VERSION, key) }
            }

            pub fn encode<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, FernetError> {
                self.encoder.encode(message, None, None)
            }

            pub fn decode<M: AsRef<[u8]>>(&self, token: M, ttl: Option<u64>) -> Result<Vec<u8>, FernetError> {
                self.encoder.decode(token, ttl)
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.key.as_mut_slice().zeroize();
            }
        }
    };
}

#[cfg(feature = "version1")]
#[derive(Clone)]
pub struct FernetToken1 {
    pub key: GenericArray<u8, U32>,
    encoder: Encoder<Aes128CbcHmac256>
}

// 1 byte for the version
// 8 bytes for the timestamp
// 16 bytes for the nonce
// 16 bytes for the block size
// 32 bytes for the mac
#[cfg(feature = "version1")]
token_impl!(FernetToken1, U32, 0x80);

#[cfg(feature = "version2")]
#[derive(Clone)]
pub struct FernetToken2 {
    pub key: GenericArray<u8, U16>,
    encoder: Encoder<Aes128Gcm>
}

// 1 byte for the version
// 8 bytes for the timestamp
// 12 bytes for the nonce
// 16 bytes for the block size
// 16 bytes for the tag
#[cfg(feature = "version2")]
token_impl!(FernetToken2, U16, 0x40);

#[cfg(feature = "version3")]
#[derive(Clone)]
pub struct FernetToken3 {
    pub key: GenericArray<u8, U32>,
    encoder: Encoder<XChaCha20Poly1305>
}

// 1 byte for the version
// 8 bytes for the timestamp
// 24 bytes for the nonce
// 32 bytes for the key size
// 16 bytes for the tag
#[cfg(feature = "version3")]
token_impl!(FernetToken3, U32, 0x20);

#[derive(Clone)]
pub struct Encoder<A: Aead + NewAead> {
    cipher: A,
    version: u8,
}

impl<A> Encoder<A> where A: Aead + NewAead {
    pub fn new(version: u8, key: &GenericArray<u8, A::KeySize>) -> Self {
        Self {
            cipher: A::new(key.clone()),
            version
        }
    }

    pub fn from_rng<R: Rng>(version: u8, rng: &mut R) -> Self {
        let mut key = vec![0u8; A::KeySize::to_usize()];
        rng.fill_bytes(key.as_mut_slice());
        Self {
            cipher: A::new(GenericArray::clone_from_slice(key.as_slice())),
            version
        }
    }

    pub fn encode<P: AsRef<[u8]>>(&self, message: P, iv: Option<GenericArray<u8, A::NonceSize>>, timestamp: Option<u64>) -> Result<Vec<u8>, FernetError> {
        let iv = match iv {
            Some(i) => i,
            None =>  {
                let mut rng = thread_rng();
                let mut v = vec![0u8; A::NonceSize::to_usize()];
                rng.fill_bytes(v.as_mut_slice());
                GenericArray::clone_from_slice(v.as_slice())
            }
        };
        let timestamp = match timestamp {
            Some(t) => t,
            None => generate_timestamp()?
        };

        let mut token = Vec::new();
        token.push(self.version);
        token.extend_from_slice(&timestamp.to_be_bytes());
        token.extend_from_slice(&iv.as_slice());

        let payload = Payload { msg: message.as_ref(), aad: token.as_slice() };
        let ciphertext = self.cipher.encrypt(&iv, payload).map_err(|_| FernetError::from(FernetErrorKind::InvalidKeyIvLength))?;
        token.extend_from_slice(ciphertext.as_slice());
        Ok(token)
    }

    pub fn decode<P: AsRef<[u8]>>(&self, token: P, ttl: Option<u64>) -> Result<Vec<u8>, FernetError> {
        let bytes = token.as_ref();

        if bytes[0] != self.version {
            return Err(FernetError::from(FernetErrorKind::InvalidVersion(self.version)));
        }

        if bytes.len() < 9 + A::NonceSize::to_usize() + A::TagSize::to_usize() {
            return Err(FernetError::from_msg(FernetErrorKind::InvalidLength, "Invalid token length"));
        }

        let timestamp = u64::from_be_bytes(*array_ref!(bytes, 1, 8));

        if let Some(expire) = ttl {
            if timestamp + expire < generate_timestamp()? {
                return Err(FernetError::from(FernetErrorKind::InvalidTimestamp));
            }
        }

        let ciphertext = Payload { msg: &bytes[(9 + A::NonceSize::to_usize())..], aad: &bytes[..(9 + A::NonceSize::to_usize())] };
        let nonce = GenericArray::from_slice(&bytes[9..(9 + A::NonceSize::to_usize())]);
        self.cipher.decrypt(nonce, ciphertext).map_err(|_| FernetError::from(FernetErrorKind::DecryptionError))
    }
}

fn generate_timestamp() -> Result<u64, FernetError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| FernetError::from_msg(FernetErrorKind::InvalidTimestamp, e.to_string()))?.as_secs())
}

#[cfg(all(feature = "version1", test))]
mod version1_tests {
    use super::*;

    #[test]
    fn encode_verify_test_1() {
        let iv = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let timestamp = 0u64;
        let key = [0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8];
        let key_array = GenericArray::from_slice(&key[..]);
        let iv_array = GenericArray::clone_from_slice(&iv[..]);

        let fernet: Encoder<Aes128CbcHmac256> = Encoder::new( FernetToken1::VERSION, key_array);
        let token = fernet.encode(b"Hello!", Some(iv_array), Some(timestamp));
        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!("800000000000000000000000000000000000000000000000000466f92679019576bd6ef6edaee434cf3ac749bedf766253b2fe11ea339ae153799128138fd4108093e2e66ca5ac85e8",
                   hex::encode(token.as_slice()));
        let res = fernet.decode(token, None);
        assert!(res.is_ok());

        let token1 = FernetToken1::new();
        let token = token1.encode(b"Hello!");
        assert!(token.is_ok());
        let decoded = token1.decode(token.unwrap(), None);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), b"Hello!".to_vec());
    }

    #[test]
    fn encode_verify_test_2() {
        //base64: DoNotUseThisIvAnywhere==
        //hex: 0e8368b54b1e4e18ac22f027cb085ead
        let iv = [14u8, 131u8, 104u8, 181u8, 75u8, 30u8, 78u8, 24u8, 172u8, 34u8, 240u8, 39u8, 203u8, 8u8, 94u8, 173u8];
        let timestamp = 1563040944;

        //base64: YouShouldNotUseThisKeyForAnythingImportant+=
        //hex: 628b92868ba574da2d52c793862b0a7b2168ac09f2b618a78089a9a2bb5a9edf
        let key = [98u8, 139u8, 146u8, 134u8,
                            139u8, 165u8, 116u8, 218u8,
                            45u8, 82u8, 199u8, 147u8,
                            134u8, 43u8, 10u8, 123u8,
                            33u8, 104u8, 172u8, 9u8,
                            242u8, 182u8, 24u8, 167u8,
                            128u8, 137u8, 169u8, 162u8,
                            187u8, 90u8, 158u8, 223u8];

        let key_array = GenericArray::from_slice(&key[..]);
        let iv_array = GenericArray::clone_from_slice(&iv[..]);

        let expected_token = base64::decode("gAAAAABdKhywDoNotUseThisIvAnywheraBsGnRWLEllkoqfR6mBc/EXmDwRB2p06ukZXfkCqpLdQoSRIDLQxIhZgMWD2LFfPg==").unwrap();

        let fernet: Encoder<Aes128CbcHmac256> = Encoder::new(FernetToken1::VERSION, key_array);
        let token = fernet.encode(b"Hello!", Some(iv_array), Some(timestamp));

        assert!(token.is_ok());
        let token = token.unwrap();
        println!("{}", base64::encode(&token));
        assert_eq!(token, expected_token);
        let res = fernet.decode(&token, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), b"Hello!");
        let res = fernet.decode(&token, Some(1));
        assert!(res.is_err());
    }

    #[test]
    fn encode_verify_test_3() {
        let fernet = FernetToken1::new();
        let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let res = fernet.encode(&text[..]);
        assert!(res.is_ok());
        let token = res.unwrap();
        assert_eq!(505, token.len());

        let res = fernet.decode(&token, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), text.to_vec());
    }
}

#[cfg(all(feature = "version2", test))]
mod version2_tests {
    use super::*;

    #[test]
    fn encode_verify_test_1() {
        let iv = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let timestamp = 0u64;
        let key = [0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8];
        let key_array = GenericArray::from_slice(&key[..]);
        let iv_array = GenericArray::clone_from_slice(&iv[..]);

        let fernet: Encoder<Aes128Gcm> = Encoder::new( FernetToken2::VERSION, key_array);
        let token = fernet.encode(b"Hello!", Some(iv_array), Some(timestamp));
        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!("4000000000000000000000000000000000000000004bedb6a20f97cb40d267945f6f0ed00b79b45b2d78c4", hex::encode(token.as_slice()));
        let res = fernet.decode(token, None);
        assert!(res.is_ok());

        let token2 = FernetToken2::new();
        let token = token2.encode(b"Hello!");
        assert!(token.is_ok());
        let decoded = token2.decode(token.unwrap(), None);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), b"Hello!".to_vec());
    }

    #[test]
    fn encode_verify_test_2() {
        //base64: DontUse++IvAtAll
        let iv = [14u8, 137u8, 237u8, 82u8, 199u8, 190u8, 248u8, 139u8, 192u8, 180u8, 9u8, 101u8];
        let timestamp = 1563040944;

        let key = b"ThisKeyIsNotSafe";
        let key_array = GenericArray::from_slice(&key[..]);
        let iv_array = GenericArray::clone_from_slice(&iv[..]);

        let expected_token = base64::decode("QAAAAABdKhywDontUse++IvAtAllj83kunazjJHWEdc3FfNVAmwZojujmA==").unwrap();

        let fernet: Encoder<Aes128Gcm> = Encoder::new(FernetToken2::VERSION, key_array);
        let token = fernet.encode(b"Hello!", Some(iv_array), Some(timestamp));

        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!(token, expected_token);
        let res = fernet.decode(&token, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), b"Hello!");
        let res = fernet.decode(&token, Some(1));
        assert!(res.is_err());
    }

    #[test]
    fn encode_verify_test_3() {
        let fernet = FernetToken2::new();
        let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let res = fernet.encode(&text[..]);
        assert!(res.is_ok());
        let token = res.unwrap();
        assert_eq!(482, token.len());

        let res = fernet.decode(&token, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), text.to_vec());
    }
}

#[cfg(all(feature = "version3", test))]
mod version3_tests {
    use super::*;

    #[test]
    fn encode_verify_test_1() {
        let iv = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let timestamp = 0u64;
        let key = [0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8,
                           0u8, 0u8, 0u8, 0u8];
        let key_array = GenericArray::from_slice(&key[..]);
        let iv_array = GenericArray::clone_from_slice(&iv[..]);

        let fernet: Encoder<XChaCha20Poly1305> = Encoder::new( FernetToken3::VERSION, key_array);
        let token = fernet.encode(b"Hello!", Some(iv_array), Some(timestamp));
        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!("20000000000000000000000000000000000000000000000000000000000000000030fbfae58a01ef10b62b525b2caa4d7ff3b16f85df7a", hex::encode(token.as_slice()));
        let res = fernet.decode(token, None);
        assert!(res.is_ok());

        let token2 = FernetToken3::new();
        let token = token2.encode(b"Hello!");
        assert!(token.is_ok());
        let decoded = token2.decode(token.unwrap(), None);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), b"Hello!".to_vec());
    }

    #[test]
    fn encode_verify_test_2() {
        //base64: DontUse++IvAtAll
        let iv = b"DontUseForAnythingSecret";
        let timestamp = 1563040944;

        let key = b"ThisKeyIsntSafeForAnythingSecret";
        let key_array = GenericArray::from_slice(&key[..]);
        let iv_array = GenericArray::clone_from_slice(&iv[..]);

        let expected_token = base64::decode("IAAAAABdKhywRG9udFVzZUZvckFueXRoaW5nU2VjcmV0ILQkuOw7QiSau9Atl9AhUGb1uAfbFA==").unwrap();

        let fernet: Encoder<XChaCha20Poly1305> = Encoder::new(FernetToken3::VERSION, key_array);
        let token = fernet.encode(b"Hello!", Some(iv_array), Some(timestamp));

        assert!(token.is_ok());
        let token = token.unwrap();
        println!("token = {}", base64::encode(&token));
        assert_eq!(token, expected_token);
        let res = fernet.decode(&token, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), b"Hello!");
        let res = fernet.decode(&token, Some(1));
        assert!(res.is_err());
    }

    #[test]
    fn encode_verify_test_3() {
        let fernet = FernetToken3::new();
        let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let res = fernet.encode(&text[..]);
        assert!(res.is_ok());
        let token = res.unwrap();
        assert_eq!(494, token.len());

        let res = fernet.decode(&token, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), text.to_vec());
    }
}
