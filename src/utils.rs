//! Miscellaneous Telnet utilities.
use crate::{constants::IAC, errors::TellyError};
use std::iter::{Fuse, FusedIterator};

/// Iterator created by [TellyIterTraits::escape_iacs].
pub struct EscapeIacs<T: Iterator<Item = u8>> {
    inner: T,
    escape_next: bool,
}

impl<T: Iterator<Item = u8>> EscapeIacs<T> {
    fn from_iterator(it: T) -> Self {
        Self {
            inner: it,
            escape_next: false,
        }
    }
}

impl<T: Iterator<Item = u8>> Iterator for EscapeIacs<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.escape_next {
            self.escape_next = false;
            Some(IAC)
        } else {
            let byte = self.inner.next();
            if byte == Some(IAC) {
                self.escape_next = true;
            };
            byte
        }
    }
}

/// Iterator created by [TellyIterTraits::unescape_iacs].
pub struct UnescapeIacs<T: Iterator<Item = u8>> {
    inner: T,
}

impl<T: Iterator<Item = u8>> UnescapeIacs<T> {
    fn from_iterator(it: T) -> Self {
        Self { inner: it }
    }
}

impl<T: Iterator<Item = u8>> Iterator for UnescapeIacs<T> {
    type Item = Result<u8, TellyError>;

    fn next(&mut self) -> Option<Self::Item> {
        let byte = self.inner.next();
        if byte == Some(IAC) {
            let next = self.inner.next();
            if next == Some(IAC) {
                Ok(next).transpose()
            } else {
                Some(Err(TellyError::DecodeError(format!(
                    "Expected '{:?}', but found '{:?}'",
                    Some(IAC),
                    next
                ))))
            }
        } else {
            Ok(byte).transpose()
        }
    }
}

/// Iterator created by [TellyIterTraits::unix_to_nvt].
pub struct UnixToNvt<T: Iterator<Item = u8>> {
    inner: T,
    produce_null: bool,
    produce_newline: bool,
}

impl<T: Iterator<Item = u8>> UnixToNvt<T> {
    fn from_iterator(it: T) -> Self {
        Self {
            inner: it,
            produce_null: false,
            produce_newline: false,
        }
    }
}

impl<T: Iterator<Item = u8>> Iterator for UnixToNvt<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.produce_null && self.produce_newline {
            unreachable!();
        }

        if self.produce_null {
            self.produce_null = false;
            Some(b'\0')
        } else if self.produce_newline {
            self.produce_newline = false;
            Some(b'\n')
        } else {
            let byte = self.inner.next();
            if byte == Some(b'\r') {
                // This is '\r\0' in Telnet
                self.produce_null = true;
                Some(b'\r')
            } else if byte == Some(b'\n') {
                // This is '\r\n' in Telnet
                self.produce_newline = true;
                Some(b'\r')
            } else {
                byte
            }
        }
    }
}

/// Iterator created by [TellyIterTraits::nvt_to_unix].
pub struct NvtToUnix<T: Iterator<Item = u8>> {
    // Needs to be fused because we look ahead
    inner: Fuse<T>,
    buffer: Option<u8>,
}

impl<T: Iterator<Item = u8>> NvtToUnix<T> {
    fn from_iterator(it: T) -> Self {
        Self {
            inner: it.fuse(),
            buffer: None,
        }
    }
}

impl<T: Iterator<Item = u8>> FusedIterator for NvtToUnix<T> {}

impl<T: Iterator<Item = u8>> Iterator for NvtToUnix<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let byte = self.buffer.take().or_else(|| self.inner.next());

        if byte == Some(b'\r') {
            // Convert '\r\n' to '\n'
            if let Some(next_byte) = self.inner.next() {
                if next_byte == b'\n' {
                    return Some(b'\n');
                } else {
                    self.buffer = Some(next_byte);
                }
            }
        // 0's are no-ops
        } else if byte == Some(0) {
            return self.next();
        }

        byte
    }
}

/// Extra iterator methods for use by Telly.
pub trait TellyIterTraits: Iterator + Sized {
    /// Escape 0xFF's in bytes, as specified by the Telnet RFC.
    ///
    /// # Example
    /// ```
    /// use telly::utils::TellyIterTraits;
    ///
    /// let bytes = vec![0xc0, 0xff, 0xee];
    /// let bytes: Vec<u8> = bytes.into_iter().escape_iacs().collect();
    /// assert_eq!(bytes, vec![0xc0, 0xff, 0xff, 0xee]);
    /// ```
    fn escape_iacs(self) -> EscapeIacs<Self>
    where
        Self: Iterator<Item = u8>,
    {
        EscapeIacs::from_iterator(self)
    }

    /// Unescape escaped Telnet bytes. Returns an error if bytes were not properly escaped.
    ///
    /// # Example
    /// ```
    /// use telly::{errors::TellyError, utils::TellyIterTraits};
    ///
    /// let bytes = vec![0xc0, 0xff, 0xff, 0xee];
    /// let bytes: Result<Vec<u8>, TellyError> = bytes.into_iter().unescape_iacs().collect();
    /// assert_eq!(bytes.unwrap(), vec![0xc0, 0xff,  0xee]);
    /// ```
    fn unescape_iacs(self) -> UnescapeIacs<Self>
    where
        Self: Iterator<Item = u8>,
    {
        UnescapeIacs::from_iterator(self)
    }

    /// Translate Unix data to Telnet data.
    ///
    /// # Example
    /// ```
    /// use telly::utils::TellyIterTraits;
    ///
    /// let bytes = "Hello World!\n";
    /// let bytes: Vec<u8> = bytes.as_bytes().iter().copied().unix_to_nvt().collect();
    /// assert_eq!(String::from_utf8_lossy(&bytes), "Hello World!\r\n");
    /// ```
    fn unix_to_nvt(self) -> UnixToNvt<EscapeIacs<Self>>
    where
        Self: Iterator<Item = u8>,
    {
        UnixToNvt::from_iterator(self.escape_iacs())
    }

    /// Translate Telnet data to Unix data. Returns an error if data is improperly encoded.
    ///
    /// Note that this strips null bytes, which can potentially destroy information.
    ///
    /// # Example
    /// ```
    /// use telly::{errors::TellyError, utils::TellyIterTraits};
    ///
    /// let bytes = "Hello World!\r\n";
    /// let bytes: Result<Vec<u8>, TellyError> =
    ///     bytes.as_bytes().iter().copied().nvt_to_unix().collect();
    /// assert_eq!(String::from_utf8_lossy(&bytes.unwrap()), "Hello World!\n");
    /// ```
    fn nvt_to_unix(self) -> UnescapeIacs<NvtToUnix<Self>>
    where
        Self: Iterator<Item = u8>,
    {
        UnescapeIacs::from_iterator(NvtToUnix::from_iterator(self))
    }
}

impl<T> TellyIterTraits for T where T: Iterator {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    #[test]
    fn escape_iacs() {
        let original = [0xaa, 0xbb, 0xff, 0xdd, 0xff];
        let expected = vec![0xaa, 0xbb, 0xff, 0xff, 0xdd, 0xff, 0xff];
        let actual: Vec<u8> = original.into_iter().escape_iacs().collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn nvt_to_unix() {
        const NUM_TESTS: usize = 1000;
        const MAX_VECTOR_SIZE: usize = 4;
        const MAX_BYTE: u8 = 255;
        // We don't want to include zero in the vector generation because they're stripped.
        const MIN_BYTE: u8 = 1;

        let mut rng = rand::thread_rng();
        for _ in 0..NUM_TESTS {
            let vec_size: usize = rng.gen_range(0..MAX_VECTOR_SIZE);
            let vec: Vec<u8> = (0..vec_size)
                .map(|_| rng.gen_range(MIN_BYTE..MAX_BYTE))
                .collect();
            let original = vec.clone();
            let encoded_decoded: Result<Vec<u8>, TellyError> =
                vec.into_iter().unix_to_nvt().nvt_to_unix().collect();

            assert_eq!(original, encoded_decoded.unwrap());
        }
    }
}
