//! Low-level CoAP operations, modified from `coap` crate.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg_attr(tarpaulin, skip)]
mod error;

pub mod header;
pub mod packet;

pub use error::CoapError;
pub use header::{MessageClass, RequestType, ResponseType};
pub use packet::CoapOption;
