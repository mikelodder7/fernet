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
use failure::{Backtrace, Context, Fail};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum FernetErrorKind {
    #[fail(display = "Invalid token length")]
    InvalidLength,
    #[fail(display = "Invalid version {}", 0)]
    InvalidVersion(u8),
    #[fail(display = "Invalid timestamp")]
    InvalidTimestamp,
    #[fail(display = "Invalid key or iv length")]
    InvalidKeyIvLength,
    #[fail(display = "Invalid mac")]
    InvalidMac,
    #[fail(display = "Token has expired")]
    ExpiredToken,
    #[fail(display = "Could not decrypt the ciphertext")]
    DecryptionError
}

#[derive(Debug)]
pub struct FernetError {
    inner: Context<FernetErrorKind>,
}

impl Fail for FernetError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl FernetError {
    pub fn from_msg<D>(kind: FernetErrorKind, msg: D) -> FernetError
    where
        D: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    {
        FernetError {
            inner: Context::new(msg).context(kind),
        }
    }

    pub fn to_kind(&self) -> FernetErrorKind {
        *self.inner.get_context()
    }
}

impl std::fmt::Display for FernetError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut first = true;

        for cause in Fail::iter_chain(&self.inner) {
            if first {
                first = false;
                writeln!(f, "Error: {}", cause)?;
            } else {
                writeln!(f, "Caused by: {}", cause)?;
            }
        }

        Ok(())
    }
}

pub fn err_msg<D>(kind: FernetErrorKind, msg: D) -> FernetError
where
    D: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
{
    FernetError::from_msg(kind, msg)
}

impl From<Context<FernetErrorKind>> for FernetError {
    fn from(inner: Context<FernetErrorKind>) -> Self {
        Self { inner }
    }
}

impl From<FernetErrorKind> for FernetError {
    fn from(e: FernetErrorKind) -> Self {
        FernetError {
            inner: Context::new("").context(e)
        }
    }
}

/// Extension methods for `Error`.
pub trait FernetErrorExt {
    fn to_fernet<D>(self, kind: FernetErrorKind, msg: D) -> FernetError
    where
        D: std::fmt::Display + Send + Sync + 'static;
}

impl<E> FernetErrorExt for E
where
    E: Fail,
{
    fn to_fernet<D>(self, kind: FernetErrorKind, msg: D) -> FernetError
    where
        D: std::fmt::Display + Send + Sync + 'static,
    {
        self.context(msg).context(kind).into()
    }
}
