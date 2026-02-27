mod bitmap;
mod commands;
mod types;

// Re-export all public items
pub use bitmap::*;
pub use commands::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afp_status_round_trip() {
        let status = FPGetSrvrInfo {
            machine_type: "Macintosh".to_string(),
            afp_versions: vec![
                AfpVersion::Version1_1,
                AfpVersion::Version2,
                AfpVersion::Version2_1,
            ],
            uams: vec![AfpUam::NoUserAuthent, AfpUam::CleartxtPasswrd],
            volume_icon: Some([0xAA; 256]), // Dummy icon
            flags: 0x0001,                  // CopyFile
            server_name: "Test Server".to_string(),
        };

        let bytes = status.to_bytes().expect("Serialization failed");

        assert_eq!(bytes.len(), 389);

        let parsed = FPGetSrvrInfo::parse(&bytes).expect("Parsing failed");

        assert_eq!(status, parsed);
    }

    #[test]
    fn test_afp_status_no_icon() {
        let status = FPGetSrvrInfo {
            machine_type: "Macintosh".to_string(),
            afp_versions: vec![AfpVersion::Version2],
            uams: vec![AfpUam::NoUserAuthent],
            volume_icon: None,
            flags: 0,
            server_name: "Mini".to_string(),
        };

        let bytes = status.to_bytes().expect("Serialization failed");
        let parsed = FPGetSrvrInfo::parse(&bytes).expect("Parsing failed");

        assert_eq!(status, parsed);
    }

    #[test]
    fn test_afp_status_binary() {
        // Packet from a PowerBook G3 server running an AFP share
        let test_data: &[u8] = &[
            0x0, 0x2b, 0x0, 0x35, 0x0, 0x63, 0x0, 0x9d, 0x80, 0xb, 0xc, 0x50, 0x6f, 0x77, 0x65,
            0x72, 0x42, 0x6f, 0x6f, 0x6b, 0x20, 0x47, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x9, 0x4d, 0x61, 0x63, 0x69, 0x6e, 0x74, 0x6f, 0x73, 0x68, 0x3, 0xe, 0x41, 0x46, 0x50,
            0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x31, 0x2e, 0x31, 0xe, 0x41, 0x46,
            0x50, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x32, 0x2e, 0x30, 0xe, 0x41,
            0x46, 0x50, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x32, 0x2e, 0x31, 0x3,
            0x10, 0x43, 0x6c, 0x65, 0x61, 0x72, 0x74, 0x78, 0x74, 0x20, 0x70, 0x61, 0x73, 0x73,
            0x77, 0x72, 0x64, 0x10, 0x52, 0x61, 0x6e, 0x64, 0x6e, 0x75, 0x6d, 0x20, 0x65, 0x78,
            0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x16, 0x32, 0x2d, 0x57, 0x61, 0x79, 0x20, 0x52,
            0x61, 0x6e, 0x64, 0x6e, 0x75, 0x6d, 0x20, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67,
            0x65, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x9f, 0xe0,
            0x0, 0x4, 0x50, 0x30, 0x0, 0x8, 0x30, 0x28, 0x0, 0x10, 0x10, 0x3c, 0x7, 0xa0, 0x8, 0x4,
            0x18, 0x7f, 0x4, 0x4, 0x10, 0x0, 0x82, 0x4, 0x10, 0x0, 0x81, 0x4, 0x10, 0x0, 0x82, 0x4,
            0x10, 0x0, 0x84, 0x4, 0x10, 0x0, 0x88, 0x4, 0x10, 0x0, 0x90, 0x4, 0x10, 0x0, 0xb0, 0x4,
            0x10, 0x0, 0xd0, 0x4, 0xff, 0xff, 0xff, 0xff, 0x40, 0x0, 0x0, 0x2, 0x3f, 0xff, 0xff,
            0xfc, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0,
            0x0, 0x0, 0xf, 0x80, 0x0, 0x0, 0x8, 0x80, 0x0, 0x0, 0x8, 0x80, 0x0, 0x0, 0xf, 0x80,
            0x0, 0x0, 0xa, 0x80, 0xbf, 0xff, 0xf2, 0x74, 0x0, 0x0, 0x5, 0x0, 0xbf, 0xff, 0xf8,
            0xf4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x3, 0x9f, 0xe0,
            0x0, 0x7, 0xdf, 0xf0, 0x0, 0xf, 0xff, 0xf8, 0x0, 0x1f, 0xff, 0xfc, 0x7, 0xbf, 0xff,
            0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f,
            0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff,
            0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0xff, 0xff, 0xff, 0xff, 0x7f,
            0xff, 0xff, 0xfe, 0x3f, 0xff, 0xff, 0xfc, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0,
            0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0xf, 0x80, 0x0, 0x0, 0xf, 0x80, 0x0, 0x0,
            0xf, 0x80, 0x0, 0x0, 0xf, 0x80, 0x0, 0x0, 0xf, 0x80, 0xbf, 0xff, 0xff, 0xf4, 0xbf,
            0xff, 0xfd, 0xf4, 0xbf, 0xff, 0xf8, 0xf4,
        ];

        let packet = FPGetSrvrInfo::parse(test_data).expect("Failed to parse test data");

        // Verify the parsed data is correct
        assert_eq!(packet.machine_type, "Macintosh");
        assert_eq!(packet.afp_versions.len(), 3);
        assert_eq!(packet.uams.len(), 3);
        assert_eq!(packet.server_name, "PowerBook G3");

        // Re-serialize and verify it can be parsed back
        let encoded = packet.to_bytes().expect("Failed to encode packet");
        let reparsed = FPGetSrvrInfo::parse(&encoded).expect("Failed to reparse encoded data");

        // Verify round-trip produces the same structure
        assert_eq!(packet, reparsed);
    }

    #[test]
    fn test_fplogin_no_auth() {
        // Test FPLogin with NoUserAuthent
        let login = FPLogin {
            afp_version: AfpVersion::Version2,
            auth: FPLoginAuth::NoUserAuthent,
        };

        let encoded = login.to_bytes().expect("Failed to encode");
        let decoded = FPLogin::parse(&encoded).expect("Failed to parse");

        assert_eq!(login, decoded);
        assert_eq!(decoded.afp_version, AfpVersion::Version2);
        assert_eq!(decoded.auth, FPLoginAuth::NoUserAuthent);
    }

    #[test]
    fn test_fplogin_cleartext() {
        // Test FPLogin with CleartxtPasswrd
        let mut password = [0u8; 8];
        password[..4].copy_from_slice(b"pass");

        let login = FPLogin {
            afp_version: AfpVersion::Version2_1,
            auth: FPLoginAuth::CleartxtPasswrd {
                username: "testuser".to_string(),
                password,
            },
        };

        let encoded = login.to_bytes().expect("Failed to encode");
        let decoded = FPLogin::parse(&encoded).expect("Failed to parse");

        assert_eq!(login, decoded);
        assert_eq!(decoded.afp_version, AfpVersion::Version2_1);

        if let FPLoginAuth::CleartxtPasswrd {
            username,
            password: pwd,
        } = decoded.auth
        {
            assert_eq!(username, "testuser");
            assert_eq!(&pwd[..4], b"pass");
            assert_eq!(&pwd[4..], &[0, 0, 0, 0]); // Verify padding
        } else {
            panic!("Expected CleartxtPasswrd auth");
        }
    }

    #[test]
    fn test_fplogin_round_trip() {
        // Test round-trip for both auth types
        let test_cases = vec![
            FPLogin {
                afp_version: AfpVersion::Version1,
                auth: FPLoginAuth::NoUserAuthent,
            },
            FPLogin {
                afp_version: AfpVersion::Version2,
                auth: FPLoginAuth::CleartxtPasswrd {
                    username: "admin".to_string(),
                    password: *b"secret\0\0",
                },
            },
        ];

        for original in test_cases {
            let encoded = original.to_bytes().expect("Failed to encode");
            let decoded = FPLogin::parse(&encoded).expect("Failed to parse");
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_fplogin_errors() {
        // Test empty buffer
        assert!(FPLogin::parse(&[]).is_err());

        // Test buffer too small for AFP version
        assert!(FPLogin::parse(&[5]).is_err());

        // Test invalid AFP version
        let invalid_version = vec![
            10, b'B', b'a', b'd', b'V', b'e', b'r', b's', b'i', b'o', b'n', 16, b'N', b'o', b' ',
            b'U', b's', b'e', b'r', b' ', b'A', b'u', b't', b'h', b'e', b'n', b't',
        ];
        assert!(FPLogin::parse(&invalid_version).is_err());

        // Test invalid UAM
        let invalid_uam = vec![
            14, b'A', b'F', b'P', b'V', b'e', b'r', b's', b'i', b'o', b'n', b' ', b'2', b'.', b'0',
            10, b'B', b'a', b'd', b'U', b'A', b'M', b'N', b'a', b'm', b'e',
        ];
        assert!(FPLogin::parse(&invalid_uam).is_err());

        // Test CleartxtPasswrd with missing password data
        let missing_password = vec![
            14, b'A', b'F', b'P', b'V', b'e', b'r', b's', b'i', b'o', b'n', b' ', b'2', b'.', b'0',
            16, b'C', b'l', b'e', b'a', b'r', b't', b'x', b't', b' ', b'P', b'a', b's', b's', b'w',
            b'r', b'd', 4, b'u', b's', b'e', b'r',
            // Missing 8 bytes for password
        ];
        assert!(FPLogin::parse(&missing_password).is_err());
    }

    #[test]
    fn test_fplogin_long_username() {
        // Test username longer than 255 characters gets truncated
        let long_username = "a".repeat(300);
        let mut password = [0u8; 8];
        password[..4].copy_from_slice(b"test");

        let login = FPLogin {
            afp_version: AfpVersion::Version2,
            auth: FPLoginAuth::CleartxtPasswrd {
                username: long_username.clone(),
                password,
            },
        };

        let encoded = login.to_bytes().expect("Failed to encode");
        let decoded = FPLogin::parse(&encoded).expect("Failed to parse");

        // Username should be truncated to 255 characters
        if let FPLoginAuth::CleartxtPasswrd { username, .. } = decoded.auth {
            assert_eq!(username.len(), 255);
            assert_eq!(username, "a".repeat(255));
        } else {
            panic!("Expected CleartxtPasswrd auth");
        }
    }
}
