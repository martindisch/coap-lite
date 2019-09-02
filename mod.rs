//! Low-level CoAP operations from `coap` crate.

pub mod header;
pub mod packet;

#[derive(Debug)]
pub enum PackageError {
    InvalidHeader,
    InvalidPacketLength,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidHeader,
    InvalidTokenLength,
    InvalidOptionDelta,
    InvalidOptionLength,
}
