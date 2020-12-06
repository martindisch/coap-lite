use super::request::CoapRequest;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Display;
use core::marker::PhantomData;

const DEFAULT_UNACKNOWLEDGED_LIMIT: u8 = 10;

type ResourcePath = String;

/// An Observer client
pub struct Observer<Endpoint: Display> {
    pub endpoint: Endpoint,
    pub token: Vec<u8>,
    unacknowledged_messages: u8,
}

/// An observed Resource
pub struct Resource<Endpoint: Display> {
    pub observers: Vec<Observer<Endpoint>>,
    pub sequence: u32,
}

/// Keeps track of the state of the observed Resources
pub struct Subject<Endpoint: Display + PartialEq> {
    resources: BTreeMap<ResourcePath, Resource<Endpoint>>,
    unacknowledged_limit: u8,
    phantom: PhantomData<Endpoint>,
}

impl<Endpoint: Display + PartialEq + Clone> Subject<Endpoint> {
    /// Register an observer interested in a resource
    pub fn register(&mut self, request: &CoapRequest<Endpoint>) {
        let observer_endpoint = request.source.as_ref().unwrap();
        let resource_path = request.get_path();
        let token = request.message.get_token();

        let observer = Observer {
            endpoint: observer_endpoint.clone(),
            token: token.clone(),
            unacknowledged_messages: 0,
        };

        let resource =
            self.resources.entry(resource_path).or_insert(Resource {
                observers: Vec::new(),
                sequence: 0,
            });

        if let Some(position) = resource
            .observers
            .iter()
            .position(|x| x.endpoint == observer.endpoint)
        {
            resource.observers[position] = observer;
        } else {
            resource.observers.push(observer);
        }
    }

    // Remove an observer from the interested resource
    pub fn deregister(&mut self, request: &CoapRequest<Endpoint>) {
        let observer_endpoint = request.source.as_ref().unwrap();
        let resource_path = request.get_path();
        let token = request.message.get_token();

        if let Some(resource) = self.resources.get_mut(&resource_path) {
            let position = resource.observers.iter().position(|x| {
                x.endpoint == *observer_endpoint && x.token == *token
            });

            if let Some(position) = position {
                resource.observers.remove(position);
            }
        }
    }

    /// Update the resource information after having notified the observers. It increments the resource
    /// sequence and counter of unacknowledged updates.
    pub fn resource_changed(&mut self, resource: &str) {
        let unacknowledged_limit = self.unacknowledged_limit;

        self.resources
            .entry(resource.to_string())
            .and_modify(|resource| {
                resource.sequence += 1;

                resource.observers.iter_mut().for_each(|observer| {
                    observer.unacknowledged_messages += 1;
                });

                resource.observers.retain(|observer| {
                    observer.unacknowledged_messages <= unacknowledged_limit
                });
            });
    }

    /// Reset the counter of unacknowledged updates for a resource observer
    pub fn acknowledge(&mut self, request: &CoapRequest<Endpoint>) {
        let observer_endpoint = request.source.as_ref().unwrap();
        let resource_path = request.get_path();
        let token = request.message.get_token();

        if let Some(resource) = self.resources.get_mut(&resource_path) {
            let observer = resource.observers.iter_mut().find(|x| {
                x.endpoint == *observer_endpoint && x.token == *token
            });

            if let Some(observer) = observer {
                observer.unacknowledged_messages = 0;
            }
        }
    }

    /// Get the tracked resources
    pub fn get_resource(&self, resource: &str) -> Option<&Resource<Endpoint>> {
        self.resources.get(resource)
    }

    /// Get the observers of a resource
    pub fn get_resource_observers(
        &self,
        resource: &str,
    ) -> Option<Vec<&Observer<Endpoint>>> {
        self.resources
            .get(resource)
            .map(|resource| resource.observers.iter().collect())
    }

    /// Set the limit of unacknowledged updates before removing an observer
    pub fn set_unacknowledged_limit(&mut self, limit: u8) {
        self.unacknowledged_limit = limit;
    }
}

impl<Endpoint: Display + PartialEq + Clone> Default for Subject<Endpoint> {
    fn default() -> Self {
        Subject {
            resources: BTreeMap::new(),
            unacknowledged_limit: DEFAULT_UNACKNOWLEDGED_LIMIT,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::{RequestType as Method, ResponseType as Status, *};
    use super::*;
    use alloc::vec;

    type Endpoint = String;

    #[test]
    fn register() {
        let resource_path = "temp";

        let mut request = CoapRequest::new();
        request.source = Some(String::from("0.0.0.0"));
        request.set_method(Method::Get);
        request.set_path(resource_path.clone());
        request.message.set_token(vec![0x7d, 0x34]);
        request
            .message
            .set_observe(vec![ObserveOption::Register as u8]);

        let mut subject: Subject<Endpoint> = Subject::default();
        subject.register(&request);

        let observers = subject
            .get_resource_observers(resource_path.clone())
            .unwrap();

        assert_eq!(observers.len(), 1);
    }

    #[test]
    fn register_replace() {
        let resource_path = "temp";

        let mut request1 = CoapRequest::new();
        request1.source = Some(String::from("0.0.0.0"));
        request1.set_method(Method::Get);
        request1.set_path(resource_path.clone());
        request1.message.set_token(vec![0x00, 0x00]);
        request1
            .message
            .set_observe(vec![ObserveOption::Register as u8]);

        let mut request2 = CoapRequest::new();
        request2.source = Some(String::from("0.0.0.0"));
        request2.set_method(Method::Get);
        request2.set_path(resource_path.clone());
        request2.message.set_token(vec![0xff, 0xff]);
        request2
            .message
            .set_observe(vec![ObserveOption::Register as u8]);

        let mut subject: Subject<Endpoint> = Subject::default();
        subject.register(&request1);
        subject.register(&request2);

        let observers = subject
            .get_resource_observers(resource_path.clone())
            .unwrap();

        assert_eq!(observers.len(), 1);

        let observer = observers.get(0).unwrap();

        assert_eq!(observer.token, vec![0xff, 0xff]);
    }

    #[test]
    fn ack_flow_ok() {
        let resource_path = "temp";

        let mut request1 = CoapRequest::new();
        request1.source = Some(String::from("0.0.0.0"));
        request1.set_method(Method::Get);
        request1.set_path(resource_path.clone());
        request1.message.set_token(vec![0x00, 0x00]);
        request1
            .message
            .set_observe(vec![ObserveOption::Register as u8]);

        let mut subject: Subject<Endpoint> = Subject::default();
        subject.register(&request1);

        let sequence1 = subject.get_resource(resource_path).unwrap().sequence;
        subject.resource_changed(resource_path);
        let sequence2 = subject.get_resource(resource_path).unwrap().sequence;

        assert!(sequence2 > sequence1);

        {
            let observers = subject
                .get_resource_observers(resource_path.clone())
                .unwrap();
            let observer = observers.get(0).unwrap();

            assert_eq!(observer.unacknowledged_messages, 1);
        }

        let mut ack = CoapRequest::new();
        ack.source = Some(String::from("0.0.0.0"));
        ack.message.header.set_type(MessageType::Acknowledgement);
        ack.set_path(resource_path.clone());
        ack.message.set_token(vec![0x00, 0x00]);

        subject.acknowledge(&ack);

        {
            let observers = subject
                .get_resource_observers(resource_path.clone())
                .unwrap();
            let observer = observers.get(0).unwrap();

            assert_eq!(observer.unacknowledged_messages, 0);
        }
    }

    #[test]
    fn ack_flow_forget_observer() {
        let resource_path = "temp";

        let mut request1 = CoapRequest::new();
        request1.source = Some(String::from("0.0.0.0"));
        request1.set_method(Method::Get);
        request1.set_path(resource_path.clone());
        request1.message.set_token(vec![0x00, 0x00]);
        request1
            .message
            .set_observe(vec![ObserveOption::Register as u8]);

        let mut subject: Subject<Endpoint> = Subject::default();
        subject.set_unacknowledged_limit(5);
        subject.register(&request1);

        subject.resource_changed(resource_path);
        subject.resource_changed(resource_path);
        subject.resource_changed(resource_path);
        subject.resource_changed(resource_path);
        subject.resource_changed(resource_path);
        subject.resource_changed(resource_path);

        let observers = subject
            .get_resource_observers(resource_path.clone())
            .unwrap();

        assert_eq!(observers.len(), 0);
    }
}
