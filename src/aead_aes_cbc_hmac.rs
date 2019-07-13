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
use aead::{Error as AeadError, Aead, NewAead, Payload};
use aead::generic_array::{GenericArray, typenum::{Unsigned, U16, U32, U64, U0}};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::{Aes128, Aes256};
use zeroize::Zeroize;
use sha2::Sha256;
use hmac::{Hmac, Mac};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

macro_rules! aead_aes_cbc_impl {
    ($name:ident, $keysize:ident, $noncesize:ident, $tagsize:ident, $algo:ident) => {
        #[derive(Clone)]
        pub struct $name {
            key: GenericArray<u8, $keysize>
        }

        impl NewAead for $name {
            type KeySize = $keysize;

            fn new(key: GenericArray<u8, $keysize>) -> Self {
                Self { key }
            }
        }

        impl Aead for $name {
            type NonceSize = $noncesize;
            type TagSize = $tagsize;
            type CiphertextOverhead = U0;

            fn encrypt<'msg, 'aad>(&self, nonce: &GenericArray<u8, Self::NonceSize>, plaintext: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>, AeadError> {
                let payload = plaintext.into();
                let encryptor = $algo::new_var(&self.key[..($keysize::to_usize() / 2)], &nonce.as_slice()).map_err(|_| AeadError)?;
                let mut ciphertext = encryptor.encrypt_vec(payload.msg);
                let mut hmac = HmacSha256::new_varkey(&self.key[($keysize::to_usize() / 2)..]).map_err(|_| AeadError)?;
                hmac.input(payload.aad);
                hmac.input(nonce.as_slice());
                hmac.input(ciphertext.as_slice());
                let hash = hmac.result().code();
                ciphertext.extend_from_slice(hash.as_slice());
                Ok(ciphertext)
            }

            fn decrypt<'msg, 'aad>(&self, nonce: &GenericArray<u8, Self::NonceSize>, ciphertext: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>, AeadError> {
                let payload = ciphertext.into();

                if payload.msg.len() < Self::TagSize::to_usize() + Self::NonceSize::to_usize() {
                    return Err(AeadError);
                }

                let tag_start = payload.msg.len() - Self::TagSize::to_usize();
                let buffer = Vec::from(&payload.msg[..tag_start]);
                let tag = Vec::from(&payload.msg[tag_start..]);

                let mut hmac = HmacSha256::new_varkey(&self.key[($keysize::to_usize() / 2)..]).map_err(|_| AeadError)?;
                hmac.input(payload.aad);
                hmac.input(nonce.as_slice());
                hmac.input(buffer.as_slice());
                let expected_tag = hmac.result().code();

                use subtle::ConstantTimeEq;
                if expected_tag.ct_eq(&tag).unwrap_u8() == 1 {
                    let decryptor = $algo::new_var(&self.key[..($keysize::to_usize() / 2)], &nonce.as_slice()).map_err(|_| AeadError)?;
                    let plaintext = decryptor.decrypt_vec(buffer.as_slice()).map_err(|_| AeadError)?;
                    Ok(plaintext)
                } else {
                    Err(AeadError)
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.key.as_mut_slice().zeroize();
            }
        }
    };
}

aead_aes_cbc_impl!(Aes128CbcHmac256, U32, U16, U32, Aes128Cbc);
aead_aes_cbc_impl!(Aes256CbcHmac256, U64, U16, U32, Aes256Cbc);
