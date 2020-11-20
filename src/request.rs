use super::header::{MessageClass, RequestType as Method};
use super::packet::{CoapOption, Packet};
use super::response::CoapResponse;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct CoapRequest<Endpoint> {
    pub message: Packet,
    pub response: Option<CoapResponse>,
    pub source: Option<Endpoint>,
}

impl<Endpoint> CoapRequest<Endpoint> {
    pub fn new() -> CoapRequest<Endpoint> {
        CoapRequest {
            response: None,
            message: Packet::new(),
            source: None,
        }
    }

    pub fn from_packet(packet: Packet, source: Endpoint) -> CoapRequest<Endpoint> {
        CoapRequest {
            response: CoapResponse::new(&packet),
            message: packet,
            source: Some(source),
        }
    }

    pub fn set_method(&mut self, method: Method) {
        self.message.header.code = MessageClass::Request(method);
    }

    pub fn get_method(&self) -> &Method {
        match self.message.header.code {
            MessageClass::Request(Method::Get) => &Method::Get,
            MessageClass::Request(Method::Post) => &Method::Post,
            MessageClass::Request(Method::Put) => &Method::Put,
            MessageClass::Request(Method::Delete) => &Method::Delete,
            _ => &Method::UnKnown,
        }
    }

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
}
