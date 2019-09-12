//! The errors of the `coap` module.

use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// The errors that can occur when encoding/decoding packets.
#[derive(Debug, PartialEq)]
pub enum MessageError {
    InvalidHeader,
    InvalidPacketLength,
    InvalidTokenLength,
    InvalidOptionDelta,
    InvalidOptionLength,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageError::InvalidHeader => {
                write!(f, "CoAP error: invalid header")
            }
            MessageError::InvalidPacketLength => {
                write!(f, "CoAP error: invalid packet length")
            }
            MessageError::InvalidTokenLength => {
                write!(f, "CoAP error: invalid token length")
            }
            MessageError::InvalidOptionDelta => {
                write!(f, "CoAP error: invalid option delta")
            }
            MessageError::InvalidOptionLength => {
                write!(f, "CoAP error: invalid option length")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for MessageError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// The error that can occur when parsing a content-format.
#[derive(Debug, PartialEq)]
pub struct InvalidContentFormat;

impl fmt::Display for InvalidContentFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CoAP error: invalid content-format number")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidContentFormat {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// The error that can occur when parsing an observe option value.
#[derive(Debug, PartialEq)]
pub struct InvalidObserve;

impl fmt::Display for InvalidObserve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CoAP error: invalid observe option number")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidObserve {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
