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

/// Extra iterator methods for use by Telly.
pub trait TellyIterTraits: Iterator + Sized {
    /// Escape 0xFF's in bytes, as specified by the Telnet RFC.
    fn escape_iacs(self) -> EscapeIacs<Self>
    where
        Self: Iterator<Item = u8>,
    {
        EscapeIacs {
            inner: self,
            escape_next: false,
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
