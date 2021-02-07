// Note that this example requires nightly for coap-handler's #![feature(iter_order_by)]

use coap_lite::{CoapRequest, Packet};
use std::net::UdpSocket;

use serde::{Deserialize, Serialize};

use coap_handler::implementations::{
    HandlerBuilder, SimpleCBORHandler, SimpleCBORWrapper, SimpleRenderable,
    TypedStaticResponse,
};
use coap_handler::Handler as _;

use coap_numbers;

fn main() {
    let mut value_at_cbor = StoredCBOR::new();

    struct Time;

    impl SimpleRenderable for Time {
        fn render<W: core::fmt::Write>(&mut self, writer: &mut W) {
            write!(
                writer,
                "It's {} seconds past epoch.",
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )
            .unwrap();
        }

        fn content_format(&self) -> Option<u16> {
            Some(0 /* text/plain */)
        }
    }

    let mut handler = coap_handler::implementations::new_dispatcher()
        .at(
            &[".well-known", "core"],
            TypedStaticResponse {
                payload: b"</>,</time>,</cbor>",
                contentformat: &[40],
            },
        )
        .at(&[], "Welcome to the Demo server")
        .at(&["time"], Time)
        .at(&["cbor"], SimpleCBORWrapper::new(&mut value_at_cbor));

    let socket = UdpSocket::bind("127.0.0.1:5683").unwrap();
    let mut buf = [0; 1280];

    loop {
        let (size, src) =
            socket.recv_from(&mut buf).expect("Didn't receive data");

        let packet = Packet::from_bytes(&buf[..size]).unwrap();
        let request = CoapRequest::from_packet(packet, src);

        let extracted = handler.extract_request_data(&request.message);

        let mut response = request.response.unwrap();
        handler.build_response(&mut response.message, extracted);

        let packet = response.message.to_bytes().unwrap();
        socket
            .send_to(&packet[..], &src)
            .expect("Could not send the data");
    }
}

// Just a more complex item for the list of resources

#[derive(Serialize, Deserialize, Clone)]
struct StoredCBOR {
    hidden: bool,
    number: usize,
    label: String,
    list: Vec<usize>,
}

impl StoredCBOR {
    fn new() -> Self {
        Self {
            hidden: false,
            number: 32,
            label: "Hello".to_string(),
            list: vec![1, 2, 3],
        }
    }
}

impl SimpleCBORHandler for &mut StoredCBOR {
    type Get = StoredCBOR;
    type Put = StoredCBOR;
    type Post = StoredCBOR;

    fn get(&mut self) -> Result<StoredCBOR, u8> {
        if self.hidden {
            return Err(coap_numbers::code::FORBIDDEN);
        }
        Ok(self.clone())
    }

    fn put(&mut self, new: &StoredCBOR) -> u8 {
        if new.label.contains("<") {
            // No HTML injection please ;-)
            return coap_numbers::code::BAD_REQUEST;
        }
        **self = new.clone();
        coap_numbers::code::CHANGED
    }

    fn post(&mut self, _: &StoredCBOR) -> u8 {
        coap_numbers::code::METHOD_NOT_ALLOWED
    }
}
