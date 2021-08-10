/// This is a very simple example using the coap_message/_handler abstractions.
///
/// For an example that shows more advanced resources, see
/// <https://gitlab.com/chrysn/coap-message-demos>, which has a coaplite
/// example of its own, and features a much larger variety of interactive
/// resources.
///
/// Note that this example requires nightly due to coap_handler's requirements.
use coap_lite::{CoapRequest, Packet};
use std::net::UdpSocket;

use coap_handler::implementations::{
    HandlerBuilder, SimpleRendered, TypedStaticResponse,
};
use coap_handler::Handler as _;

fn main() {
    let mut handler = coap_handler::implementations::new_dispatcher()
        .at(
            &[".well-known", "core"],
            TypedStaticResponse {
                payload: b"</>,</time>",
                contentformat: &[40],
            },
        )
        .at(&[], SimpleRendered("Welcome to the Demo server"));

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
