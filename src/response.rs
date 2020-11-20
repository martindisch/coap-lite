use super::header::{MessageClass, MessageType, ResponseType as Status};
use super::packet::Packet;

#[derive(Clone, Debug)]
pub struct CoapResponse {
    pub message: Packet,
}

impl CoapResponse {
    pub fn new(request: &Packet) -> Option<CoapResponse> {
        let mut packet = Packet::new();

        packet.header.set_version(1);
        let response_type = match request.header.get_type() {
            MessageType::Confirmable => MessageType::Acknowledgement,
            MessageType::NonConfirmable => MessageType::NonConfirmable,
            _ => return None,
        };
        packet.header.set_type(response_type);
        packet.header.code = MessageClass::Response(Status::Content);
        packet
            .header
            .set_message_id(request.header.get_message_id());
        packet.set_token(request.get_token().clone());

        packet.payload = request.payload.clone();

        Some(CoapResponse { message: packet })
    }

    pub fn set_status(&mut self, status: Status) {
        self.message.header.code = MessageClass::Response(status);
    }

    pub fn get_status(&self) -> &Status {
        match self.message.header.code {
            MessageClass::Response(Status::Created) => &Status::Created,
            MessageClass::Response(Status::Deleted) => &Status::Deleted,
            MessageClass::Response(Status::Valid) => &Status::Valid,
            MessageClass::Response(Status::Changed) => &Status::Changed,
            MessageClass::Response(Status::Content) => &Status::Content,

            MessageClass::Response(Status::BadRequest) => &Status::BadRequest,
            MessageClass::Response(Status::Unauthorized) => &Status::Unauthorized,
            MessageClass::Response(Status::BadOption) => &Status::BadOption,
            MessageClass::Response(Status::Forbidden) => &Status::Forbidden,
            MessageClass::Response(Status::NotFound) => &Status::NotFound,
            MessageClass::Response(Status::MethodNotAllowed) => &Status::MethodNotAllowed,
            MessageClass::Response(Status::NotAcceptable) => &Status::NotAcceptable,
            MessageClass::Response(Status::PreconditionFailed) => &Status::PreconditionFailed,
            MessageClass::Response(Status::RequestEntityTooLarge) => &Status::RequestEntityTooLarge,
            MessageClass::Response(Status::UnsupportedContentFormat) => {
                &Status::UnsupportedContentFormat
            }

            MessageClass::Response(Status::InternalServerError) => &Status::InternalServerError,
            MessageClass::Response(Status::NotImplemented) => &Status::NotImplemented,
            MessageClass::Response(Status::BadGateway) => &Status::BadGateway,
            MessageClass::Response(Status::ServiceUnavailable) => &Status::ServiceUnavailable,
            MessageClass::Response(Status::GatewayTimeout) => &Status::GatewayTimeout,
            MessageClass::Response(Status::ProxyingNotSupported) => &Status::ProxyingNotSupported,
            _ => &Status::UnKnown,
        }
    }
}
