//! Low-level CoAP operations, modified from `coap` crate.

use core::fmt;

pub mod header;
pub mod packet;

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
