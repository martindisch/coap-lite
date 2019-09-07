//! The errors of the `coap` module.

use core::fmt;

#[derive(Debug)]
pub enum CoapError {
    InvalidHeader,
    InvalidPacketLength,
    InvalidTokenLength,
    InvalidOptionDelta,
    InvalidOptionLength,
}

impl fmt::Display for CoapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CoapError::InvalidHeader => {
                write!(f, "CoAP error: invalid header")
            }
            CoapError::InvalidPacketLength => {
                write!(f, "CoAP error: invalid packet length")
            }
            CoapError::InvalidTokenLength => {
                write!(f, "CoAP error: invalid token length")
            }
            CoapError::InvalidOptionDelta => {
                write!(f, "CoAP error: invalid option delta")
            }
            CoapError::InvalidOptionLength => {
                write!(f, "CoAP error: invalid option length")
            }
        }
    }
}

#[derive(Debug)]
pub struct InvalidOption;

impl fmt::Display for InvalidOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CoAP error: invalid option number")
    }
}

#[derive(Debug)]
pub struct InvalidContentFormat;

impl fmt::Display for InvalidContentFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CoAP error: invalid content-format number")
    }
}

#[derive(Debug)]
pub struct InvalidObserve;

impl fmt::Display for InvalidObserve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CoAP error: invalid observe option number")
    }
}
