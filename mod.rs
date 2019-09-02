//! Low-level CoAP operations, modified from `coap` crate.

#[cfg_attr(tarpaulin, skip)]
mod error;

pub mod header;
pub mod packet;

pub use error::CoapError;
pub use packet::CoapOption;
