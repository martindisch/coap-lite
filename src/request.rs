use super::header::MessageClass;
use super::header::RequestType as Method;
use super::packet::{CoapOption, ObserveOption, Packet};
use super::response::CoapResponse;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The CoAP request.
#[derive(Clone, Debug)]
pub struct CoapRequest<Endpoint> {
    pub message: Packet,
    pub response: Option<CoapResponse>,
    pub source: Option<Endpoint>,
}

impl<Endpoint> CoapRequest<Endpoint> {
    /// Creates a new request.
    pub fn new() -> CoapRequest<Endpoint> {
        CoapRequest {
            response: None,
            message: Packet::new(),
            source: None,
        }
    }

    /// Creates a request from a packet.
    pub fn from_packet(packet: Packet, source: Endpoint) -> CoapRequest<Endpoint> {
        CoapRequest {
            response: CoapResponse::new(&packet),
            message: packet,
            source: Some(source),
        }
    }

    /// Sets the method.
    pub fn set_method(&mut self, method: Method) {
        self.message.header.code = MessageClass::Request(method);
    }

    /// Returns the method.
    pub fn get_method(&self) -> &Method {
        match self.message.header.code {
            MessageClass::Request(Method::Get) => &Method::Get,
            MessageClass::Request(Method::Post) => &Method::Post,
            MessageClass::Request(Method::Put) => &Method::Put,
            MessageClass::Request(Method::Delete) => &Method::Delete,
            _ => &Method::UnKnown,
        }
    }

    /// Sets the path.
    pub fn set_path(&mut self, path: &str) {
        self.message.clear_option(CoapOption::UriPath);

        let segs = path.split('/');
        for (i, s) in segs.enumerate() {
            if i == 0 && s.is_empty() {
                continue;
            }

            self.message
                .add_option(CoapOption::UriPath, s.as_bytes().to_vec());
        }
    }

    /// Returns the path.
    pub fn get_path(&self) -> String {
        match self.message.get_option(CoapOption::UriPath) {
            Some(options) => {
                let mut vec = Vec::new();
                for option in options.iter() {
                    if let Ok(seg) = core::str::from_utf8(option) {
                        vec.push(seg);
                    }
                }
                vec.join("/")
            }
            _ => "".to_string(),
        }
    }

    /// Returns the flag in the Observe option
    pub fn get_observe_flag(&self) -> Option<ObserveOption> {
        self.message
            .get_observe()
            .and_then(|option| match option.get(0) {
                Some(&x) if x == ObserveOption::Register as u8 => Some(ObserveOption::Register),
                Some(&x) if x == ObserveOption::Deregister as u8 => Some(ObserveOption::Deregister),
                Some(_) => None,
                None => Some(ObserveOption::Register), // Value is Register by default if not present
            })
    }
}

#[cfg(test)]
mod test {
    use super::super::header::MessageType;
    use super::super::packet::{CoapOption, Packet};
    use super::*;
    use alloc::string::String;

    struct Endpoint(String);

    #[test]
    fn test_request_create() {
        let mut packet = Packet::new();
        let mut request1: CoapRequest<Endpoint> = CoapRequest::new();

        packet.set_token(vec![0x17, 0x38]);
        request1.message.set_token(vec![0x17, 0x38]);

        packet.add_option(CoapOption::UriPath, b"test-interface".to_vec());
        request1
            .message
            .add_option(CoapOption::UriPath, b"test-interface".to_vec());

        packet.header.message_id = 42;
        request1.message.header.message_id = 42;

        packet.header.set_version(2);
        request1.message.header.set_version(2);

        packet.header.set_type(MessageType::Confirmable);
        request1.message.header.set_type(MessageType::Confirmable);

        packet.header.set_code("0.04");
        request1.message.header.set_code("0.04");

        let endpoint = Endpoint(String::from("127.0.0.1:1234"));
        let request2 = CoapRequest::from_packet(packet, endpoint);

        assert_eq!(
            request1.message.to_bytes().unwrap(),
            request2.message.to_bytes().unwrap()
        );
    }

    #[test]
    fn test_method() {
        let mut request: CoapRequest<Endpoint> = CoapRequest::new();

        request.message.header.set_code("0.01");
        assert_eq!(&Method::Get, request.get_method());

        request.message.header.set_code("0.02");
        assert_eq!(&Method::Post, request.get_method());

        request.message.header.set_code("0.03");
        assert_eq!(&Method::Put, request.get_method());

        request.message.header.set_code("0.04");
        assert_eq!(&Method::Delete, request.get_method());

        request.set_method(Method::Get);
        assert_eq!("0.01", request.message.header.get_code());

        request.set_method(Method::Post);
        assert_eq!("0.02", request.message.header.get_code());

        request.set_method(Method::Put);
        assert_eq!("0.03", request.message.header.get_code());

        request.set_method(Method::Delete);
        assert_eq!("0.04", request.message.header.get_code());
    }

    #[test]
    fn test_path() {
        let mut request: CoapRequest<Endpoint> = CoapRequest::new();

        let path = "test-interface";
        request
            .message
            .add_option(CoapOption::UriPath, path.as_bytes().to_vec());
        assert_eq!(path, request.get_path());

        let path2 = "test-interface2";
        request.set_path(path2);
        assert_eq!(
            path2.as_bytes().to_vec(),
            *request
                .message
                .get_option(CoapOption::UriPath)
                .unwrap()
                .front()
                .unwrap()
        );

        request.set_path("/test-interface2");
        assert_eq!(
            path2.as_bytes().to_vec(),
            *request
                .message
                .get_option(CoapOption::UriPath)
                .unwrap()
                .front()
                .unwrap()
        );

        let path3 = "test-interface2/";
        request.set_path(path3);
        assert_eq!(path3, request.get_path());
    }
}
