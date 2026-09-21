//! NBP name registration and LkUp responder.
//!
//! Registration is local only: on a routerless cable there is no router to
//! confirm names with, and with a router present duplicate suppression is
//! the registrant's problem.
//!
//! LkUp requests arrive as broadcasts on DDP socket 2; on a routerless cable
//! a Mac's BrRq is sent as a broadcast LkUp directly, and with a router the
//! router forwards the BrRq as a LkUp whose DDP source is the router but
//! whose request tuple names the original requester. Replies therefore go to
//! the tuple's address, never the DDP source.

use alloc::vec::Vec;
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::heapless;
use tailtalk_packets::limits::{MAX_NBP_TUPLES, NbpName};
use tailtalk_packets::nbp::{EntityName, NbpOperation, NbpPacket, NbpTuple};

/// The zone every reply tuple carries. A printer registers in "this zone",
/// which is what `*` means on the wire; a router rewrites it if it cares.
const ZONE_WILDCARD: &[u8] = b"*";

/// The well-known Names Information Socket.
pub const NBP_SOCKET: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredName {
    pub name: EntityName,
    pub socket: u8,
}

/// Where a LkUp-Reply must be sent.
#[derive(Debug, Clone, PartialEq)]
pub struct NbpReply {
    pub dest: AppleTalkAddress,
    pub dest_socket: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct NbpRegistry {
    names: Vec<RegisteredName>,
}

impl NbpRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a name to answer lookups for. Fails on wildcard names and
    /// exact duplicates.
    pub fn register(&mut self, name: EntityName, socket: u8) -> Result<(), &'static str> {
        if !name.fully_qualified() {
            return Err("entity name contains wildcards");
        }
        let entry = RegisteredName { name, socket };
        if self.names.contains(&entry) {
            return Err("entity name and socket already registered");
        }
        self.names.push(entry);
        Ok(())
    }

    pub fn unregister(&mut self, name: &EntityName, socket: u8) -> bool {
        let before = self.names.len();
        self.names
            .retain(|n| !(n.name == *name && n.socket == socket));
        self.names.len() < before
    }

    pub fn registered(&self) -> &[RegisteredName] {
        &self.names
    }

    /// Handle an NBP packet received on socket 2. Returns the reply to send,
    /// if any. `our_addr` is our current DDP address; the reply tuples carry
    /// it so the requester knows where the service lives.
    pub fn handle_packet(&self, payload: &[u8], our_addr: AppleTalkAddress) -> Option<NbpReply> {
        let packet = NbpPacket::from_bytes(payload).ok()?;
        if !matches!(packet.operation, NbpOperation::Lookup) {
            return None;
        }

        let zone = NbpName::from_wire(ZONE_WILDCARD)?;
        let mut tuples: heapless::Vec<NbpTuple, MAX_NBP_TUPLES> = heapless::Vec::new();
        'outer: for req_tuple in &packet.tuples {
            for name in &self.names {
                if name.name.matches(&req_tuple.entity_name) {
                    let tuple = NbpTuple {
                        network_number: our_addr.network_number,
                        node_id: our_addr.node_number,
                        socket_number: name.socket,
                        enumerator: 0,
                        entity_name: EntityName {
                            object: name.name.object,
                            entity_type: name.name.entity_type,
                            zone,
                        },
                    };
                    // NBP packs the tuple count into a nibble, so a reply
                    // cannot carry more than 15. Send what fits rather than
                    // dropping the reply outright.
                    if tuples.push(tuple).is_err() {
                        break 'outer;
                    }
                }
            }
        }
        if tuples.is_empty() {
            return None;
        }

        // Reply to the request tuple's address, not the DDP source; see the
        // module docs for why they differ behind a router.
        let req_tuple = packet.tuples.first()?;
        let reply = NbpPacket {
            operation: NbpOperation::LookupReply,
            transaction_id: packet.transaction_id,
            tuples,
        };
        let mut buf = [0u8; 600];
        let size = reply.to_bytes(&mut buf).ok()?;
        Some(NbpReply {
            dest: AppleTalkAddress {
                network_number: req_tuple.network_number,
                node_number: req_tuple.node_id,
            },
            dest_socket: req_tuple.socket_number,
            payload: buf[..size].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_packet(pattern: &str, tid: u8) -> Vec<u8> {
        let mut tuples = heapless::Vec::new();
        // `push` returns Err(the rejected value), and NbpTuple is not
        // Debug, so assert on the result rather than unwrapping it.
        assert!(
            tuples
                .push(NbpTuple {
                    network_number: 0,
                    node_id: 41,
                    socket_number: 2,
                    enumerator: 0,
                    entity_name: pattern.try_into().unwrap(),
                })
                .is_ok(),
            "one tuple fits"
        );
        let packet = NbpPacket {
            operation: NbpOperation::Lookup,
            transaction_id: tid,
            tuples,
        };
        let mut buf = [0u8; 600];
        let n = packet.to_bytes(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn answers_matching_lookup_at_tuple_address() {
        let mut reg = NbpRegistry::new();
        reg.register("Inky:ImageWriter@*".try_into().unwrap(), 190)
            .unwrap();

        let us = AppleTalkAddress {
            network_number: 0,
            node_number: 130,
        };
        let reply = reg
            .handle_packet(&lookup_packet("=:ImageWriter@*", 9), us)
            .expect("lookup should match");
        assert_eq!(reply.dest.node_number, 41);
        assert_eq!(reply.dest_socket, 2);

        let parsed = NbpPacket::from_bytes(&reply.payload).unwrap();
        assert!(matches!(parsed.operation, NbpOperation::LookupReply));
        assert_eq!(parsed.transaction_id, 9);
        assert_eq!(parsed.tuples.len(), 1);
        let tuple = &parsed.tuples[0];
        assert_eq!(tuple.node_id, 130);
        assert_eq!(tuple.socket_number, 190);
        assert_eq!(tuple.entity_name.object.as_wire(), b"Inky");
        assert_eq!(tuple.entity_name.zone.as_wire(), b"*");
    }

    #[test]
    fn silent_on_no_match() {
        let mut reg = NbpRegistry::new();
        reg.register("Inky:ImageWriter@*".try_into().unwrap(), 190)
            .unwrap();
        let us = AppleTalkAddress {
            network_number: 0,
            node_number: 130,
        };
        assert!(
            reg.handle_packet(&lookup_packet("=:LaserWriter@*", 1), us)
                .is_none()
        );
    }

    #[test]
    fn wildcard_registration_is_rejected() {
        let mut reg = NbpRegistry::new();
        assert!(
            reg.register("=:ImageWriter@*".try_into().unwrap(), 190)
                .is_err()
        );
    }
}
