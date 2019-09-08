# coap-lite
[![Latest version](https://img.shields.io/crates/v/coap-lite)](https://crates.io/crates/coap-lite)
[![Documentation](https://docs.rs/coap-lite/badge.svg)](https://docs.rs/coap-lite)
[![License](https://img.shields.io/crates/l/coap-lite)](https://github.com/martindisch/coap-lite#license)

<!-- cargo-sync-readme start -->

A lightweight, `#![no_std]` CoAP message manipulation crate, ideal for
embedded environments.

It's based on the improved low-level message handling code from the [coap]
crate, made to work in bare metal environments.

## Overview
This crate provides several types that can be used to build, modify and
encode/decode CoAP messages to/from their byte representation.

It does require allocation, so you might have to set a global allocator
depending on your target.

## Usage
```rust
use coap_lite::{
    CoapOption, MessageClass, MessageType,
    Packet, RequestType, ResponseType,
};

let mut request = Packet::new();
request.header.message_id = 23839;
request.header.code = MessageClass::Request(RequestType::Get);
request.set_token(vec![0, 0, 57, 116]);
request.add_option(CoapOption::UriHost, b"localhost".to_vec());
request.add_option(CoapOption::UriPath, b"tv1".to_vec());
assert_eq!(
    [
        0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F,
        0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
    ],
    request.to_bytes().unwrap()[..]
);

let response = Packet::from_bytes(&[
    0x64, 0x45, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0xFF, 0x48, 0x65,
    0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
])
.unwrap();
assert_eq!(23839, response.header.message_id);
assert_eq!(
    MessageClass::Response(ResponseType::Content),
    response.header.code
);
assert_eq!(MessageType::Acknowledgement, response.header.get_type());
assert_eq!([0, 0, 57, 116], response.get_token()[..]);
assert_eq!(b"Hello World!", &response.payload[..]);
```

[coap]: https://github.com/covertness/coap-rs

<!-- cargo-sync-readme end -->

## License
Licensed under either of

 * [Apache License, Version 2.0](LICENSE-APACHE)
 * [MIT license](LICENSE-MIT)

at your option.

This is a modification of the [coap](https://github.com/covertness/coap-rs)
crate, its license is in
[LICENSE-3RD-PARTY](LICENSE-3RD-PARTY).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
