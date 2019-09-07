use alloc::{
    collections::{BTreeMap, LinkedList},
    vec::Vec,
};
use core::convert::TryFrom;

use super::{
    error::{CoapError, InvalidContentFormat, InvalidObserve, InvalidOption},
    header,
};

macro_rules! u8_to_unsigned_be {
    ($src:ident, $start:expr, $end:expr, $t:ty) => ({
        (0..=$end - $start).rev().fold(
            0, |acc, i| acc | $src[$start+i] as $t << i * 8
        )
    })
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum CoapOption {
    IfMatch,
    UriHost,
    ETag,
    IfNoneMatch,
    Observe,
    UriPort,
    LocationPath,
    Oscore,
    UriPath,
    ContentFormat,
    MaxAge,
    UriQuery,
    Accept,
    LocationQuery,
    Block2,
    Block1,
    ProxyUri,
    ProxyScheme,
    Size1,
    Size2,
    NoResponse,
}

impl TryFrom<usize> for CoapOption {
    type Error = InvalidOption;

    fn try_from(number: usize) -> Result<CoapOption, InvalidOption> {
        match number {
            1 => Ok(CoapOption::IfMatch),
            3 => Ok(CoapOption::UriHost),
            4 => Ok(CoapOption::ETag),
            5 => Ok(CoapOption::IfNoneMatch),
            6 => Ok(CoapOption::Observe),
            7 => Ok(CoapOption::UriPort),
            8 => Ok(CoapOption::LocationPath),
            9 => Ok(CoapOption::Oscore),
            11 => Ok(CoapOption::UriPath),
            12 => Ok(CoapOption::ContentFormat),
            14 => Ok(CoapOption::MaxAge),
            15 => Ok(CoapOption::UriQuery),
            17 => Ok(CoapOption::Accept),
            20 => Ok(CoapOption::LocationQuery),
            23 => Ok(CoapOption::Block2),
            27 => Ok(CoapOption::Block1),
            35 => Ok(CoapOption::ProxyUri),
            39 => Ok(CoapOption::ProxyScheme),
            60 => Ok(CoapOption::Size1),
            28 => Ok(CoapOption::Size2),
            258 => Ok(CoapOption::NoResponse),
            _ => Err(InvalidOption),
        }
    }
}

impl From<CoapOption> for usize {
    fn from(option: CoapOption) -> usize {
        match option {
            CoapOption::IfMatch => 1,
            CoapOption::UriHost => 3,
            CoapOption::ETag => 4,
            CoapOption::IfNoneMatch => 5,
            CoapOption::Observe => 6,
            CoapOption::UriPort => 7,
            CoapOption::LocationPath => 8,
            CoapOption::Oscore => 9,
            CoapOption::UriPath => 11,
            CoapOption::ContentFormat => 12,
            CoapOption::MaxAge => 14,
            CoapOption::UriQuery => 15,
            CoapOption::Accept => 17,
            CoapOption::LocationQuery => 20,
            CoapOption::Block2 => 23,
            CoapOption::Block1 => 27,
            CoapOption::ProxyUri => 35,
            CoapOption::ProxyScheme => 39,
            CoapOption::Size1 => 60,
            CoapOption::Size2 => 28,
            CoapOption::NoResponse => 258,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum ContentFormat {
    TextPlain,
    ApplicationLinkFormat,
    ApplicationXML,
    ApplicationOctetStream,
    ApplicationEXI,
    ApplicationJSON,
    ApplicationCBOR,
    ApplicationSenmlJSON,
    ApplicationSensmlJSON,
    ApplicationSenmlCBOR,
    ApplicationSensmlCBOR,
    ApplicationSenmlExi,
    ApplicationSensmlExi,
    ApplicationSenmlXML,
    ApplicationSensmlXML,
}

impl TryFrom<usize> for ContentFormat {
    type Error = InvalidContentFormat;

    fn try_from(number: usize) -> Result<ContentFormat, InvalidContentFormat> {
        match number {
            0 => Ok(ContentFormat::TextPlain),
            40 => Ok(ContentFormat::ApplicationLinkFormat),
            41 => Ok(ContentFormat::ApplicationXML),
            42 => Ok(ContentFormat::ApplicationOctetStream),
            47 => Ok(ContentFormat::ApplicationEXI),
            50 => Ok(ContentFormat::ApplicationJSON),
            60 => Ok(ContentFormat::ApplicationCBOR),
            110 => Ok(ContentFormat::ApplicationSenmlJSON),
            111 => Ok(ContentFormat::ApplicationSensmlJSON),
            112 => Ok(ContentFormat::ApplicationSenmlCBOR),
            113 => Ok(ContentFormat::ApplicationSensmlCBOR),
            114 => Ok(ContentFormat::ApplicationSenmlExi),
            115 => Ok(ContentFormat::ApplicationSensmlExi),
            310 => Ok(ContentFormat::ApplicationSenmlXML),
            311 => Ok(ContentFormat::ApplicationSensmlXML),
            _ => Err(InvalidContentFormat),
        }
    }
}

impl From<ContentFormat> for usize {
    fn from(format: ContentFormat) -> usize {
        match format {
            ContentFormat::TextPlain => 0,
            ContentFormat::ApplicationLinkFormat => 40,
            ContentFormat::ApplicationXML => 41,
            ContentFormat::ApplicationOctetStream => 42,
            ContentFormat::ApplicationEXI => 47,
            ContentFormat::ApplicationJSON => 50,
            ContentFormat::ApplicationCBOR => 60,
            ContentFormat::ApplicationSenmlJSON => 110,
            ContentFormat::ApplicationSensmlJSON => 111,
            ContentFormat::ApplicationSenmlCBOR => 112,
            ContentFormat::ApplicationSensmlCBOR => 113,
            ContentFormat::ApplicationSenmlExi => 114,
            ContentFormat::ApplicationSensmlExi => 115,
            ContentFormat::ApplicationSenmlXML => 310,
            ContentFormat::ApplicationSensmlXML => 311,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum ObserveOption {
    Register,
    Deregister,
}

impl TryFrom<usize> for ObserveOption {
    type Error = InvalidObserve;

    fn try_from(number: usize) -> Result<ObserveOption, InvalidObserve> {
        match number {
            0 => Ok(ObserveOption::Register),
            1 => Ok(ObserveOption::Deregister),
            _ => Err(InvalidObserve),
        }
    }
}

impl From<ObserveOption> for usize {
    fn from(observe: ObserveOption) -> usize {
        match observe {
            ObserveOption::Register => 0,
            ObserveOption::Deregister => 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: header::Header,
    token: Vec<u8>,
    options: BTreeMap<usize, LinkedList<Vec<u8>>>,
    pub payload: Vec<u8>,
}

pub type Options<'a> =
    alloc::collections::btree_map::Iter<'a, usize, LinkedList<Vec<u8>>>;

impl Packet {
    pub fn new() -> Packet {
        Packet {
            header: header::Header::new(),
            token: Vec::new(),
            options: BTreeMap::new(),
            payload: Vec::new(),
        }
    }

    pub fn options(&self) -> Options {
        self.options.iter()
    }

    pub fn set_token(&mut self, token: Vec<u8>) {
        self.header.set_token_length(token.len() as u8);
        self.token = token;
    }

    pub fn get_token(&self) -> &Vec<u8> {
        &self.token
    }

    pub fn set_option(&mut self, tp: CoapOption, value: LinkedList<Vec<u8>>) {
        self.options.insert(tp.into(), value);
    }

    pub fn set_content_format(&mut self, cf: ContentFormat) {
        let content_format: usize = cf.into();
        let msb = (content_format >> 8) as u8;
        let lsb = (content_format & 0xFF) as u8;

        let content_format: Vec<u8> = vec![msb, lsb];
        self.add_option(CoapOption::ContentFormat, content_format);
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn add_option(&mut self, tp: CoapOption, value: Vec<u8>) {
        let num = tp.into();
        if let Some(list) = self.options.get_mut(&num) {
            list.push_back(value);
            return;
        }

        let mut list = LinkedList::new();
        list.push_back(value);
        self.options.insert(num, list);
    }

    pub fn get_option(&self, tp: CoapOption) -> Option<&LinkedList<Vec<u8>>> {
        self.options.get(&tp.into())
    }

    pub fn clear_option(&mut self, tp: CoapOption) {
        if let Some(list) = self.options.get_mut(&tp.into()) {
            list.clear()
        }
    }

    pub fn get_content_format(&self) -> Option<ContentFormat> {
        if let Some(list) = self.get_option(CoapOption::ContentFormat) {
            if let Some(vector) = list.front() {
                let msb = u16::from(vector[0]);
                let lsb = u16::from(vector[1]);
                let number = (msb << 8) + lsb;

                return ContentFormat::try_from(number as usize).ok();
            }
        }

        None
    }

    pub fn set_observe(&mut self, value: Vec<u8>) {
        self.clear_option(CoapOption::Observe);
        self.add_option(CoapOption::Observe, value);
    }

    pub fn get_observe(&self) -> Option<&Vec<u8>> {
        if let Some(list) = self.get_option(CoapOption::Observe) {
            if let Some(flag) = list.front() {
                return Some(flag);
            }
        }

        None
    }

    /// Decodes a byte slice and construct the equivalent Packet.
    pub fn from_bytes(buf: &[u8]) -> Result<Packet, CoapError> {
        let header_result = header::HeaderRaw::try_from(buf);
        match header_result {
            Ok(raw_header) => {
                let header = header::Header::from_raw(&raw_header);
                let token_length = header.get_token_length();
                let options_start: usize = 4 + token_length as usize;

                if token_length > 8 {
                    return Err(CoapError::InvalidTokenLength);
                }

                if options_start > buf.len() {
                    return Err(CoapError::InvalidTokenLength);
                }

                let token = buf[4..options_start].to_vec();

                let mut idx = options_start;
                let mut options_number = 0;
                let mut options: BTreeMap<usize, LinkedList<Vec<u8>>> =
                    BTreeMap::new();
                while idx < buf.len() {
                    let byte = buf[idx];

                    if byte == 255 || idx > buf.len() {
                        break;
                    }

                    let mut delta = (byte >> 4) as usize;
                    let mut length = (byte & 0xF) as usize;

                    idx += 1;

                    // Check for special delta characters
                    match delta {
                        13 => {
                            if idx >= buf.len() {
                                return Err(CoapError::InvalidOptionLength);
                            }
                            delta = buf[idx] as usize + 13;
                            idx += 1;
                        }
                        14 => {
                            if idx + 1 >= buf.len() {
                                return Err(CoapError::InvalidOptionLength);
                            }

                            delta = (u16::from_be(u8_to_unsigned_be!(
                                buf,
                                idx,
                                idx + 1,
                                u16
                            )) + 269)
                                as usize;
                            idx += 2;
                        }
                        15 => {
                            return Err(CoapError::InvalidOptionDelta);
                        }
                        _ => {}
                    };

                    // Check for special length characters
                    match length {
                        13 => {
                            if idx >= buf.len() {
                                return Err(CoapError::InvalidOptionLength);
                            }

                            length = buf[idx] as usize + 13;
                            idx += 1;
                        }
                        14 => {
                            if idx + 1 >= buf.len() {
                                return Err(CoapError::InvalidOptionLength);
                            }

                            length = (u16::from_be(u8_to_unsigned_be!(
                                buf,
                                idx,
                                idx + 1,
                                u16
                            )) + 269)
                                as usize;
                            idx += 2;
                        }
                        15 => {
                            return Err(CoapError::InvalidOptionLength);
                        }
                        _ => {}
                    };

                    options_number += delta;

                    let end = idx + length;
                    if end > buf.len() {
                        return Err(CoapError::InvalidOptionLength);
                    }
                    let options_value = buf[idx..end].to_vec();

                    options
                        .entry(options_number)
                        .or_insert_with(LinkedList::new)
                        .push_back(options_value);

                    idx += length;
                }

                let payload = if idx < buf.len() {
                    buf[(idx + 1)..buf.len()].to_vec()
                } else {
                    Vec::new()
                };

                Ok(Packet {
                    header,
                    token,
                    options,
                    payload,
                })
            }
            Err(_) => Err(CoapError::InvalidHeader),
        }
    }

    /// Returns a vector of bytes representing the Packet.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CoapError> {
        let mut options_delta_length = 0;
        let mut options_bytes: Vec<u8> = Vec::new();
        for (number, value_list) in self.options.iter() {
            for value in value_list.iter() {
                let mut header: Vec<u8> = Vec::with_capacity(1 + 2 + 2);
                let delta = number - options_delta_length;

                let mut byte: u8 = 0;
                if delta <= 12 {
                    byte |= (delta << 4) as u8;
                } else if delta < 269 {
                    byte |= 13 << 4;
                } else {
                    byte |= 14 << 4;
                }
                if value.len() <= 12 {
                    byte |= value.len() as u8;
                } else if value.len() < 269 {
                    byte |= 13;
                } else {
                    byte |= 14;
                }
                header.push(byte);

                if delta > 12 && delta < 269 {
                    header.push((delta - 13) as u8);
                } else if delta >= 269 {
                    let fix = (delta - 269) as u16;
                    header.push((fix >> 8) as u8);
                    header.push((fix & 0xFF) as u8);
                }

                if value.len() > 12 && value.len() < 269 {
                    header.push((value.len() - 13) as u8);
                } else if value.len() >= 269 {
                    let fix = (value.len() - 269) as u16;
                    header.push((fix >> 8) as u8);
                    header.push((fix & 0xFF) as u8);
                }

                options_delta_length += delta;

                options_bytes.reserve(header.len() + value.len());
                unsafe {
                    use core::ptr;
                    let buf_len = options_bytes.len();
                    ptr::copy(
                        header.as_ptr(),
                        options_bytes.as_mut_ptr().add(buf_len),
                        header.len(),
                    );
                    ptr::copy(
                        value.as_ptr(),
                        options_bytes.as_mut_ptr().add(buf_len + header.len()),
                        value.len(),
                    );
                    options_bytes
                        .set_len(buf_len + header.len() + value.len());
                }
            }
        }

        let mut buf_length = 4 + self.payload.len() + self.token.len();
        if self.header.code != header::MessageClass::Empty
            && !self.payload.is_empty()
        {
            buf_length += 1;
        }
        buf_length += options_bytes.len();

        if buf_length > 1280 {
            return Err(CoapError::InvalidPacketLength);
        }

        let mut buf: Vec<u8> = Vec::with_capacity(buf_length);
        let header_result = self.header.to_raw().serialize_into(&mut buf);

        match header_result {
            Ok(_) => {
                buf.reserve(self.token.len() + options_bytes.len());
                unsafe {
                    use core::ptr;
                    let buf_len = buf.len();
                    ptr::copy(
                        self.token.as_ptr(),
                        buf.as_mut_ptr().add(buf_len),
                        self.token.len(),
                    );
                    ptr::copy(
                        options_bytes.as_ptr(),
                        buf.as_mut_ptr().add(buf_len + self.token.len()),
                        options_bytes.len(),
                    );
                    buf.set_len(
                        buf_len + self.token.len() + options_bytes.len(),
                    );
                }

                if self.header.code != header::MessageClass::Empty
                    && !self.payload.is_empty()
                {
                    buf.push(0xFF);
                    buf.reserve(self.payload.len());
                    unsafe {
                        use core::ptr;
                        let buf_len = buf.len();
                        ptr::copy(
                            self.payload.as_ptr(),
                            buf.as_mut_ptr().add(buf.len()),
                            self.payload.len(),
                        );
                        buf.set_len(buf_len + self.payload.len());
                    }
                }
                Ok(buf)
            }
            Err(_) => Err(CoapError::InvalidHeader),
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::header;
    use super::*;

    #[test]
    fn test_decode_packet_with_options() {
        let buf = [
            0x44, 0x01, 0x84, 0x9e, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48, 0x69,
            0x04, 0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31,
        ];
        let packet = Packet::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.header.get_version(), 1);
        assert_eq!(packet.header.get_type(), header::MessageType::Confirmable);
        assert_eq!(packet.header.get_token_length(), 4);
        assert_eq!(
            packet.header.code,
            header::MessageClass::Request(header::RequestType::Get)
        );
        assert_eq!(packet.header.get_message_id(), 33950);
        assert_eq!(*packet.get_token(), vec![0x51, 0x55, 0x77, 0xE8]);
        assert_eq!(packet.options.len(), 2);

        let uri_path = packet.get_option(CoapOption::UriPath);
        assert!(uri_path.is_some());
        let uri_path = uri_path.unwrap();
        let mut expected_uri_path = LinkedList::new();
        expected_uri_path.push_back("Hi".as_bytes().to_vec());
        expected_uri_path.push_back("Test".as_bytes().to_vec());
        assert_eq!(*uri_path, expected_uri_path);

        let uri_query = packet.get_option(CoapOption::UriQuery);
        assert!(uri_query.is_some());
        let uri_query = uri_query.unwrap();
        let mut expected_uri_query = LinkedList::new();
        expected_uri_query.push_back("a=1".as_bytes().to_vec());
        assert_eq!(*uri_query, expected_uri_query);
    }

    #[test]
    fn test_decode_packet_with_payload() {
        let buf = [
            0x64, 0x45, 0x13, 0xFD, 0xD0, 0xE2, 0x4D, 0xAC, 0xFF, 0x48, 0x65,
            0x6C, 0x6C, 0x6F,
        ];
        let packet = Packet::from_bytes(&buf);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.header.get_version(), 1);
        assert_eq!(
            packet.header.get_type(),
            header::MessageType::Acknowledgement
        );
        assert_eq!(packet.header.get_token_length(), 4);
        assert_eq!(
            packet.header.code,
            header::MessageClass::Response(header::ResponseType::Content)
        );
        assert_eq!(packet.header.get_message_id(), 5117);
        assert_eq!(*packet.get_token(), vec![0xD0, 0xE2, 0x4D, 0xAC]);
        assert_eq!(packet.payload, "Hello".as_bytes().to_vec());
    }

    #[test]
    fn test_encode_packet_with_options() {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.set_type(header::MessageType::Confirmable);
        packet.header.code =
            header::MessageClass::Request(header::RequestType::Get);
        packet.header.set_message_id(33950);
        packet.set_token(vec![0x51, 0x55, 0x77, 0xE8]);
        packet.add_option(CoapOption::UriPath, b"Hi".to_vec());
        packet.add_option(CoapOption::UriPath, b"Test".to_vec());
        packet.add_option(CoapOption::UriQuery, b"a=1".to_vec());
        assert_eq!(
            packet.to_bytes().unwrap(),
            vec![
                0x44, 0x01, 0x84, 0x9e, 0x51, 0x55, 0x77, 0xe8, 0xb2, 0x48,
                0x69, 0x04, 0x54, 0x65, 0x73, 0x74, 0x43, 0x61, 0x3d, 0x31
            ]
        );
    }

    #[test]
    fn test_encode_packet_with_payload() {
        let mut packet = Packet::new();
        packet.header.set_version(1);
        packet.header.set_type(header::MessageType::Acknowledgement);
        packet.header.code =
            header::MessageClass::Response(header::ResponseType::Content);
        packet.header.set_message_id(5117);
        packet.set_token(vec![0xD0, 0xE2, 0x4D, 0xAC]);
        packet.payload = "Hello".as_bytes().to_vec();
        assert_eq!(
            packet.to_bytes().unwrap(),
            vec![
                0x64, 0x45, 0x13, 0xFD, 0xD0, 0xE2, 0x4D, 0xAC, 0xFF, 0x48,
                0x65, 0x6C, 0x6C, 0x6F
            ]
        );
    }

    #[test]
    fn test_encode_decode_content_format() {
        let mut packet = Packet::new();
        packet.set_content_format(ContentFormat::ApplicationJSON);
        assert_eq!(
            ContentFormat::ApplicationJSON,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_decode_empty_content_format() {
        let packet = Packet::new();
        assert!(packet.get_content_format().is_none());
    }

    // #[test]
    // fn test_malicious_packet() {
    //     use quickcheck::{QuickCheck, StdThreadGen, TestResult};

    //     fn run(x: Vec<u8>) -> TestResult {
    //         match Packet::from_bytes(&x[..]) {
    //             Ok(packet) => TestResult::from_bool(
    //                 packet.get_token().len()
    //                     == packet.header.get_token_length() as usize,
    //             ),
    //             Err(_) => TestResult::passed(),
    //         }
    //     }
    //     QuickCheck::new()
    //         .tests(10000)
    //         .gen(StdThreadGen::new(1500))
    //         .quickcheck(run as fn(Vec<u8>) -> TestResult)
    // }
}
