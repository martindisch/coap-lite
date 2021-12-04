use alloc::{
    collections::{BTreeMap, LinkedList},
    vec::Vec,
};
use core::convert::TryFrom;

use crate::{
    error::{
        IncompatibleOptionValueFormat, InvalidContentFormat, InvalidObserve,
        MessageError,
    },
    header::{Header, HeaderRaw, MessageClass},
    option_value::{OptionValueType, OptionValueU16, OptionValueU32},
};

macro_rules! u8_to_unsigned_be {
    ($src:ident, $start:expr, $end:expr, $t:ty) => ({
        (0..=$end - $start).rev().fold(
            0, |acc, i| acc | $src[$start+i] as $t << i * 8
        )
    })
}

/// The CoAP options.
#[derive(Debug, Clone, Copy, PartialEq)]
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
    Unknown(u16),
}

impl From<u16> for CoapOption {
    fn from(number: u16) -> CoapOption {
        match number {
            1 => CoapOption::IfMatch,
            3 => CoapOption::UriHost,
            4 => CoapOption::ETag,
            5 => CoapOption::IfNoneMatch,
            6 => CoapOption::Observe,
            7 => CoapOption::UriPort,
            8 => CoapOption::LocationPath,
            9 => CoapOption::Oscore,
            11 => CoapOption::UriPath,
            12 => CoapOption::ContentFormat,
            14 => CoapOption::MaxAge,
            15 => CoapOption::UriQuery,
            17 => CoapOption::Accept,
            20 => CoapOption::LocationQuery,
            23 => CoapOption::Block2,
            27 => CoapOption::Block1,
            35 => CoapOption::ProxyUri,
            39 => CoapOption::ProxyScheme,
            60 => CoapOption::Size1,
            28 => CoapOption::Size2,
            258 => CoapOption::NoResponse,
            _ => CoapOption::Unknown(number),
        }
    }
}

impl From<CoapOption> for u16 {
    fn from(option: CoapOption) -> u16 {
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
            CoapOption::Unknown(number) => number,
        }
    }
}

/// The content formats.
#[derive(Debug, Clone, Copy, PartialEq)]
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

/// The values of the observe option.
#[derive(Debug, Clone, Copy, PartialEq)]
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

/// The CoAP packet.
#[derive(Debug, Clone, Default)]
pub struct Packet {
    pub header: Header,
    token: Vec<u8>,
    pub(crate) options: BTreeMap<u16, LinkedList<Vec<u8>>>,
    pub payload: Vec<u8>,
}

/// An iterator over the options of a packet.
pub type Options<'a> =
    alloc::collections::btree_map::Iter<'a, u16, LinkedList<Vec<u8>>>;

impl Packet {
    /// Creates a new packet.
    pub fn new() -> Packet {
        Default::default()
    }

    /// Returns an iterator over the options of the packet.
    pub fn options(&self) -> Options {
        self.options.iter()
    }

    /// Sets the token.
    pub fn set_token(&mut self, token: Vec<u8>) {
        self.header.set_token_length(token.len() as u8);
        self.token = token;
    }

    /// Returns the token.
    pub fn get_token(&self) -> &[u8] {
        &self.token
    }

    /// Sets an option's values.
    pub fn set_option(&mut self, tp: CoapOption, value: LinkedList<Vec<u8>>) {
        self.options.insert(tp.into(), value);
    }

    /// Sets an option's values using a structured option value format.
    pub fn set_options_as<T: OptionValueType>(
        &mut self,
        tp: CoapOption,
        value: LinkedList<T>,
    ) {
        let raw_value = value.into_iter().map(|x| x.into()).collect();
        self.set_option(tp, raw_value);
    }

    /// Returns an option's values.
    pub fn get_option(&self, tp: CoapOption) -> Option<&LinkedList<Vec<u8>>> {
        self.options.get(&tp.into())
    }

    /// Returns an option's values all decoded using the specified structured
    /// option value format.
    pub fn get_options_as<T: OptionValueType>(
        &self,
        tp: CoapOption,
    ) -> Option<LinkedList<Result<T, IncompatibleOptionValueFormat>>> {
        self.get_option(tp).map(|options| {
            options
                .iter()
                .map(|raw_value| T::try_from(raw_value.clone()))
                .collect()
        })
    }

    /// Returns an option's first value as a convenience when only one is
    /// expected.
    pub fn get_first_option(&self, tp: CoapOption) -> Option<&Vec<u8>> {
        self.options
            .get(&tp.into())
            .and_then(|options| options.front())
    }

    /// Returns an option's first value as a convenience when only one is
    /// expected.
    pub fn get_first_option_as<T: OptionValueType>(
        &self,
        tp: CoapOption,
    ) -> Option<Result<T, IncompatibleOptionValueFormat>> {
        self.get_first_option(tp)
            .map(|value| T::try_from(value.clone()))
    }

    /// Adds an option value.
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

    /// Adds an option value using a structured option value format.
    pub fn add_option_as<T: OptionValueType>(
        &mut self,
        tp: CoapOption,
        value: T,
    ) {
        self.add_option(tp, value.into());
    }

    /// Removes an option.
    pub fn clear_option(&mut self, tp: CoapOption) {
        if let Some(list) = self.options.get_mut(&tp.into()) {
            list.clear()
        }
    }

    /// Sets the content-format.
    pub fn set_content_format(&mut self, cf: ContentFormat) {
        let content_format: u16 = u16::try_from(usize::from(cf)).unwrap();
        self.add_option_as(
            CoapOption::ContentFormat,
            OptionValueU16(content_format),
        );
    }

    /// Returns the content-format.
    pub fn get_content_format(&self) -> Option<ContentFormat> {
        self.get_first_option_as::<OptionValueU16>(CoapOption::ContentFormat)
            .and_then(|option| option.ok())
            .map(|value| usize::try_from(value.0).unwrap())
            .and_then(|value| ContentFormat::try_from(value).ok())
    }

    /// Sets the value of the observe option.
    pub fn set_observe_value(&mut self, value: u32) {
        self.clear_option(CoapOption::Observe);
        self.add_option_as(CoapOption::Observe, OptionValueU32(value));
    }

    /// Returns the value of the observe option.
    pub fn get_observe_value(
        &self,
    ) -> Option<Result<u32, IncompatibleOptionValueFormat>> {
        self.get_first_option_as::<OptionValueU32>(CoapOption::Observe)
            .map(|option| option.map(|value| value.0))
    }

    /// Decodes a byte slice and constructs the equivalent packet.
    pub fn from_bytes(buf: &[u8]) -> Result<Packet, MessageError> {
        let header_result = HeaderRaw::try_from(buf);
        match header_result {
            Ok(raw_header) => {
                let header = Header::from_raw(&raw_header);
                let token_length = header.get_token_length();
                let options_start: usize = 4 + token_length as usize;

                if token_length > 8 {
                    return Err(MessageError::InvalidTokenLength);
                }

                if options_start > buf.len() {
                    return Err(MessageError::InvalidTokenLength);
                }

                let token = buf[4..options_start].to_vec();

                let mut idx = options_start;
                let mut options_number = 0;
                let mut options: BTreeMap<u16, LinkedList<Vec<u8>>> =
                    BTreeMap::new();
                while idx < buf.len() {
                    let byte = buf[idx];

                    if byte == 255 || idx > buf.len() {
                        break;
                    }

                    let mut delta = (byte >> 4) as u16;
                    let mut length = (byte & 0xF) as usize;

                    idx += 1;

                    // Check for special delta characters
                    match delta {
                        13 => {
                            if idx >= buf.len() {
                                return Err(MessageError::InvalidOptionLength);
                            }
                            delta = (buf[idx] + 13).into();
                            idx += 1;
                        }
                        14 => {
                            if idx + 1 >= buf.len() {
                                return Err(MessageError::InvalidOptionLength);
                            }

                            delta = u16::from_be(u8_to_unsigned_be!(
                                buf,
                                idx,
                                idx + 1,
                                u16
                            )) + 269;
                            idx += 2;
                        }
                        15 => {
                            return Err(MessageError::InvalidOptionDelta);
                        }
                        _ => {}
                    };

                    // Check for special length characters
                    match length {
                        13 => {
                            if idx >= buf.len() {
                                return Err(MessageError::InvalidOptionLength);
                            }

                            length = buf[idx] as usize + 13;
                            idx += 1;
                        }
                        14 => {
                            if idx + 1 >= buf.len() {
                                return Err(MessageError::InvalidOptionLength);
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
                            return Err(MessageError::InvalidOptionLength);
                        }
                        _ => {}
                    };

                    options_number += delta;

                    let end = idx + length;
                    if end > buf.len() {
                        return Err(MessageError::InvalidOptionLength);
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
            Err(_) => Err(MessageError::InvalidHeader),
        }
    }

    /// Returns a vector of bytes representing the Packet.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
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
        if self.header.code != MessageClass::Empty && !self.payload.is_empty()
        {
            buf_length += 1;
        }
        buf_length += options_bytes.len();

        if buf_length > 1280 {
            return Err(MessageError::InvalidPacketLength);
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

                if self.header.code != MessageClass::Empty
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
            Err(_) => Err(MessageError::InvalidHeader),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{header, option_value::OptionValueString};
    use alloc::borrow::ToOwned;

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
        assert_eq!(packet.header.message_id, 33950);
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
        assert_eq!(packet.header.message_id, 5117);
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
        packet.header.message_id = 33950;
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
        packet.header.message_id = 5117;
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
        packet.set_content_format(ContentFormat::TextPlain);
        assert_eq!(
            ContentFormat::TextPlain,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_encode_decode_content_format_without_msb() {
        let mut packet = Packet::new();
        packet.set_content_format(ContentFormat::ApplicationJSON);
        assert_eq!(
            ContentFormat::ApplicationJSON,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_encode_decode_content_format_with_msb() {
        let mut packet = Packet::new();
        packet.set_content_format(ContentFormat::ApplicationSensmlXML);
        assert_eq!(
            ContentFormat::ApplicationSensmlXML,
            packet.get_content_format().unwrap()
        )
    }

    #[test]
    fn test_decode_empty_content_format() {
        let packet = Packet::new();
        assert!(packet.get_content_format().is_none());
    }

    #[test]
    fn option() {
        for i in 0..512 {
            match CoapOption::try_from(i) {
                Ok(o) => assert_eq!(i, o.into()),
                _ => (),
            }
        }
    }

    #[test]
    fn content_format() {
        for i in 0..512 {
            match ContentFormat::try_from(i) {
                Ok(o) => assert_eq!(i, o.into()),
                _ => (),
            }
        }
    }

    #[test]
    fn observe_option() {
        for i in 0..8 {
            match ObserveOption::try_from(i) {
                Ok(o) => assert_eq!(i, o.into()),
                _ => (),
            }
        }
    }

    #[test]
    fn options() {
        let mut p = Packet::new();
        p.add_option(CoapOption::UriHost, vec![0]);
        p.add_option(CoapOption::UriPath, vec![1]);
        p.add_option(CoapOption::ETag, vec![2]);
        p.clear_option(CoapOption::ETag);
        assert_eq!(3, p.options().len());

        let bytes = p.to_bytes().unwrap();
        let mut pp = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(2, pp.options().len());

        let mut values = LinkedList::new();
        values.push_back(vec![3]);
        values.push_back(vec![4]);
        pp.set_option(CoapOption::Oscore, values);
        assert_eq!(3, pp.options().len());
    }

    #[test]
    fn test_option_u32_format() {
        let mut p = Packet::new();
        let option_key = CoapOption::Observe;
        let values = vec![0, 100, 1000, 10000, u32::MAX];
        for &value in &values {
            p.add_option_as(option_key, OptionValueU32(value));
        }
        let expected = values.iter().map(|&x| Ok(OptionValueU32(x))).collect();
        let actual = p.get_options_as::<OptionValueU32>(option_key);
        assert_eq!(actual, Some(expected));
    }

    #[test]
    fn test_option_utf8_format() {
        let mut p = Packet::new();
        let option_key = CoapOption::UriPath;
        let values = vec!["", "simple", "unicode 😁 stuff"];
        for &value in &values {
            p.add_option_as(option_key, OptionValueString(value.to_owned()));
        }
        let expected = values
            .iter()
            .map(|&x| Ok(OptionValueString(x.to_owned())))
            .collect();
        let actual = p.get_options_as::<OptionValueString>(option_key);
        assert_eq!(actual, Some(expected));
    }

    #[test]
    fn observe() {
        let mut p = Packet::new();
        assert_eq!(None, p.get_observe_value());
        p.set_observe_value(0);
        assert_eq!(Some(Ok(0)), p.get_observe_value());
    }
}
