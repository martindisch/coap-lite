//! Low-level CoAP operations, modified from `coap` crate.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg_attr(tarpaulin, skip)]
pub mod error;

mod header;
mod packet;

pub use header::{
    Header, HeaderRaw, MessageClass, MessageType, RequestType, ResponseType,
};
pub use packet::{CoapOption, ContentFormat, Packet};
