#![warn(missing_docs)]
//! Miscellaneous Telnet utilities.
use crate::TelnetCommand;

/// Iterator created by [TellyIterTraits::escape_iacs].
pub struct EscapeIacs<T: Iterator<Item = u8>> {
    inner: T,
    escape_next: bool,
}

impl<T: Iterator<Item = u8>> Iterator for EscapeIacs<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.escape_next {
            self.escape_next = false;
            Some(TelnetCommand::IAC.into())
        } else {
            let byte = self.inner.next();
            if byte == Some(TelnetCommand::IAC.into()) {
                self.escape_next = true;
            };
            byte
        }
    }
}

/// Iterator created by [TellyIterTraits::unix_to_nvt].
pub struct UnixToNvt<T: Iterator<Item = u8>> {
    inner: T,
    produce_null: bool,
    produce_newline: bool,
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
        EscapeIacs {
            inner: self,
            escape_next: false,
        }
    }

    /// Translate Unix data to Telnet dataa.
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
        UnixToNvt {
            inner: self.escape_iacs(),
            produce_newline: false,
            produce_null: false,
        }
    }
}

impl<T> TellyIterTraits for T where T: Iterator {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escape_iacs() {
        let original = [0xaa, 0xbb, 0xff, 0xdd, 0xff];
        let expected = vec![0xaa, 0xbb, 0xff, 0xff, 0xdd, 0xff, 0xff];
        let actual: Vec<u8> = original.into_iter().escape_iacs().collect();
        assert_eq!(expected, actual);
    }
}
