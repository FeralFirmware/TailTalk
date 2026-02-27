#![allow(dead_code)]

use std::fmt::Display;

/// Represents an NBP packet for AppleTalk.
#[derive(Debug)]
pub struct NbpPacket {
    pub operation: NbpOperation, // NBP operation type
    pub transaction_id: u8,      // Transaction ID for matching requests and responses
    pub tuples: Vec<NbpTuple>,   // List of NBP tuples
}

/// Enum for NBP operation types.
#[derive(Debug)]
#[repr(u8)]
pub enum NbpOperation {
    BroadcastRequest = 1,
    Lookup = 2,
    LookupReply = 3,
    ForwardRequest = 4,
    Unknown(u8),
}

impl NbpOperation {
    /// Parse a u8 into an NbpOperation.
    fn from_u8(value: u8) -> Self {
        match value {
            1 => NbpOperation::BroadcastRequest,
            2 => NbpOperation::Lookup,
            3 => NbpOperation::LookupReply,
            4 => NbpOperation::ForwardRequest,
            _ => NbpOperation::Unknown(value),
        }
    }

    /// Convert an NbpOperation into a u8.
    fn to_u8(&self) -> u8 {
        match self {
            NbpOperation::BroadcastRequest => 1,
            NbpOperation::Lookup => 2,
            NbpOperation::LookupReply => 3,
            NbpOperation::ForwardRequest => 4,
            NbpOperation::Unknown(value) => *value,
        }
    }
}

/// Represents a single NBP tuple.
#[derive(Debug)]
pub struct NbpTuple {
    pub network_number: u16,     // 2-byte network number
    pub node_id: u8,             // 1-byte node ID
    pub socket_number: u8,       // 1-byte socket number
    pub enumerator: u8,          // 1-byte enumerator
    pub entity_name: EntityName, // The entity name (object, type, zone)
}

/// Represents an entity name in NBP.
#[derive(Debug, Eq, PartialEq)]
pub struct EntityName {
    pub object: String,      // Object name
    pub entity_type: String, // Type of the entity (e.g., service type)
    pub zone: String,        // Zone name
}

impl NbpPacket {
    /// Parses an NBP packet from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 2 {
            return Err("Packet too short to be valid".to_string());
        }

        let control_byte = data[0];
        let operation = NbpOperation::from_u8(control_byte >> 4);
        let tuple_count = control_byte & 0x0F;
        let transaction_id = data[1];
        let mut offset = 2;
        let mut tuples = Vec::new();

        for _ in 0..tuple_count {
            if offset + 5 > data.len() {
                return Err("Packet too short for declared tuple count".to_string());
            }

            tracing::info!("Handling first part");
            let network_number = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let node_id = data[offset + 2];
            let socket_number = data[offset + 3];
            let enumerator = data[offset + 4];
            offset += 5;

            tracing::info!("Handlnig second part");
            let (entity_name, name_length) = EntityName::from_bytes(&data[offset..])?;
            offset += name_length;

            tracing::info!("handling third part");
            tuples.push(NbpTuple {
                network_number,
                node_id,
                socket_number,
                enumerator,
                entity_name,
            });
        }

        tracing::info!("returning packet");
        Ok(NbpPacket {
            operation,
            transaction_id,
            tuples,
        })
    }

    /// Serializes the NBP packet into a byte slice.
    /// Returns the size of the serialized data.
    pub fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize, String> {
        let mut offset = 0;

        if buffer.len() < 2 {
            return Err("Buffer too small to hold the header".to_string());
        }

        // Write control byte (operation and tuple count)
        buffer[offset] = (self.operation.to_u8() << 4) | (self.tuples.len() as u8 & 0x0F);
        offset += 1;

        // Write transaction ID
        buffer[offset] = self.transaction_id;
        offset += 1;

        // Write tuples
        for tuple in &self.tuples {
            if offset + 5 > buffer.len() {
                return Err("Buffer too small to hold tuple data".to_string());
            }

            buffer[offset..offset + 2].copy_from_slice(&tuple.network_number.to_be_bytes());
            offset += 2;

            buffer[offset] = tuple.node_id;
            offset += 1;

            buffer[offset] = tuple.socket_number;
            offset += 1;

            buffer[offset] = tuple.enumerator;
            offset += 1;

            let entity_name_size = tuple.entity_name.to_bytes(&mut buffer[offset..])?;
            offset += entity_name_size;
        }

        Ok(offset)
    }
}

impl TryFrom<&str> for EntityName {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let first_index = value
            .find(":")
            .ok_or("malformed entity name - missing : separator")?;
        let second_index = value
            .find("@")
            .ok_or("malformed entity name - missing @ separator")?;

        if first_index > second_index {
            return Err("malformed entity name - : was found before @");
        }

        let object = &value[..first_index];
        if object.is_empty() {
            return Err("malformed entity name - object is empty");
        }

        let entity_type = &value[first_index + 1..second_index];
        if entity_type.is_empty() {
            return Err("malformed entity name - type is empty");
        }

        let zone = &value[second_index + 1..];
        if zone.is_empty() {
            return Err("malformed entity name - zone is empty");
        }

        Ok(EntityName {
            object: object.into(),
            entity_type: entity_type.into(),
            zone: zone.into(),
        })
    }
}

impl Display for EntityName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}@{}", self.object, self.entity_type, self.zone)
    }
}

impl EntityName {
    /// Parses an entity name (object, type, zone) from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), String> {
        let mut offset = 0;

        let object_length = *data.get(offset).ok_or("Missing object length")? as usize;
        offset += 1;

        let (object_cow, _, _) =
            encoding_rs::MACINTOSH.decode(&data[offset..offset + object_length]);
        let object = object_cow.into_owned();
        offset += object_length;

        let type_length = *data.get(offset).ok_or("Missing type length")? as usize;
        offset += 1;

        let (type_cow, _, _) = encoding_rs::MACINTOSH.decode(&data[offset..offset + type_length]);
        let entity_type = type_cow.into_owned();
        offset += type_length;

        let zone_length = *data.get(offset).ok_or("Missing zone length")? as usize;
        offset += 1;
        let (zone_cow, _, _) = encoding_rs::MACINTOSH.decode(&data[offset..offset + zone_length]);
        let zone = zone_cow.into_owned();
        offset += zone_length;

        Ok((
            EntityName {
                object,
                entity_type,
                zone,
            },
            offset,
        ))
    }

    /// Serializes the entity name into a byte slice.
    /// Returns the size of the serialized data.
    pub fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize, String> {
        let mut offset = 0;

        let (object_cow, _, _) = encoding_rs::MACINTOSH.encode(self.object.as_str());
        let object = object_cow.into_owned();
        let (type_cow, _, _) = encoding_rs::MACINTOSH.encode(self.entity_type.as_str());
        let entity_type = type_cow.into_owned();
        let (zone_cow, _, _) = encoding_rs::MACINTOSH.encode(self.zone.as_str());
        let zone = zone_cow.into_owned();

        let calc_size = 1 + object.len() + 1 + entity_type.len() + 1 + zone.len();
        if buffer.len() < calc_size {
            return Err(format!(
                "Buffer too small to hold entity name. Buf is: {}, calc_size: {calc_size}",
                buffer.len()
            ));
        }

        buffer[offset] = object.len() as u8;
        offset += 1;
        buffer[offset..offset + object.len()].copy_from_slice(&object);
        offset += object.len();

        buffer[offset] = entity_type.len() as u8;
        offset += 1;
        buffer[offset..offset + entity_type.len()].copy_from_slice(&entity_type);
        offset += entity_type.len();

        buffer[offset] = zone.len() as u8;
        offset += 1;
        buffer[offset..offset + zone.len()].copy_from_slice(&zone);
        offset += zone.len();

        Ok(offset)
    }

    pub fn matches(&self, pattern: &EntityName) -> bool {
        let match_part = |concrete: &str, pattern: &str| -> bool {
            if pattern == "=" || pattern == "≈" || pattern == "*" {
                return true;
            }
            concrete.eq_ignore_ascii_case(pattern)
        };

        match_part(&self.object, &pattern.object)
            && match_part(&self.entity_type, &pattern.entity_type)
            && match_part(&self.zone, &pattern.zone)
    }

    pub fn fully_qualified(&self) -> bool {
        const LOOKUP_FLAGS: [char; 3] = ['*', '=', '≈'];

        for flag in LOOKUP_FLAGS {
            if self.object.contains(flag) || self.entity_type.contains(flag) || self.zone != "*" {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nbp() {
        const TEST_DATA: &[u8] = &[
            0x21, 0x01, 0xff, 0x54, 0x44, 0xfe, 0x00, 0x20, 0x30, 0x41, 0x45, 0x30, 0x34, 0x39,
            0x36, 0x30, 0x33, 0x30, 0x44, 0x42, 0x43, 0x34, 0x30, 0x34, 0x31, 0x38, 0x30, 0x30,
            0x41, 0x44, 0x43, 0x44, 0x30, 0x34, 0x37, 0x40, 0x4d, 0x4f, 0x52, 0x4f, 0x1c, 0x4d,
            0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0xa8, 0x20, 0x57, 0x69, 0x6e, 0x64,
            0x6f, 0x77, 0x73, 0x20, 0x32, 0x30, 0x30, 0x30, 0xaa, 0x20, 0x50, 0x72, 0x74, 0x01,
            0x2a,
        ];

        let packet = NbpPacket::from_bytes(TEST_DATA).expect("failed to parse");
        let mut buf = [0u8; TEST_DATA.len()];

        packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(TEST_DATA, buf);
    }

    #[test]
    fn test_parse_entity() {
        let example_name = "Judy:Mailbox@Bandley3";

        let entity: EntityName = example_name.try_into().expect("failed to parse");

        assert_eq!(entity.object, "Judy");
        assert_eq!(entity.entity_type, "Mailbox");
        assert_eq!(entity.zone, "Bandley3");
    }

    #[test]
    fn test_malformed_entity() {
        assert!(EntityName::try_from("").is_err());
        assert!(EntityName::try_from(":@").is_err());
        assert!(EntityName::try_from("pants@waffles:com").is_err());
        assert!(EntityName::try_from("Pannenkoek:Waffles@").is_err());
        assert!(EntityName::try_from("Pannenkoek:@Waffles").is_err());
        assert!(EntityName::try_from("Pannenkoek:@@@:").is_err());
    }
    #[test]
    fn test_matches() {
        let name: EntityName = "Steve:Workstation@Twilight".try_into().unwrap();

        // Exact match
        assert!(name.matches(&"Steve:Workstation@Twilight".try_into().unwrap()));

        // Case insensitive
        assert!(name.matches(&"steve:workstation@twilight".try_into().unwrap()));

        // Wildcards
        assert!(name.matches(&"=:=@*".try_into().unwrap()));

        assert!(name.matches(&"≈:Workstation@*".try_into().unwrap()));

        // Mismatches
        assert!(!name.matches(&"Bob:Workstation@Twilight".try_into().unwrap()));

        assert!(!name.matches(&"Steve:Printer@Twilight".try_into().unwrap()));
    }
}
